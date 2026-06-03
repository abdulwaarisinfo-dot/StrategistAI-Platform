# ================================================================
# AI E-COMMERCE STRATEGY PLATFORM
# Author:  Waris Ali — AI Solutions Developer
# Stack:   FastAPI · MongoDB · OpenAI · WebSockets · JWT
# Version: 2.0.0
# ================================================================

from fastapi import (
    FastAPI, HTTPException, Depends, Form,
    Request, WebSocket, WebSocketDisconnect
)
from fastapi.security import OAuth2PasswordBearer
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware

from jose import jwt, JWTError
from passlib.context import CryptContext
from dotenv import load_dotenv
from pymongo import MongoClient, DESCENDING
from openai import OpenAI

import certifi
import os
import logging
import random
import re
from datetime import datetime, timedelta, timezone
from typing import Dict, Optional

# ================================================================
# ENVIRONMENT
# ================================================================

load_dotenv()

# ================================================================
# LOGGING
# ================================================================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s"
)
logger = logging.getLogger("ecommerce.platform.v2")

# ================================================================
# CONSTANTS
# ================================================================

ALGORITHM       = "HS256"
TOKEN_EXPIRE_H  = 12
MAX_BCRYPT_LEN  = 72
RESET_CODE_TTL  = 15          # minutes
MAX_GENERATIONS = 10          # free tier daily limit — no paid plans
MAX_HISTORY     = 10          # last N generations stored per user

# ================================================================
# ENV VARIABLES
# ================================================================

MONGO_URI     = os.getenv("MONGO_URI", "")
JWT_SECRET    = os.getenv("JWT_SECRET_KEY", "")
OPENAI_KEY    = os.getenv("OPENAI_API_KEY", "")

if not all([MONGO_URI, JWT_SECRET, OPENAI_KEY]):
    logger.critical("Missing required environment variables. Check .env file.")
    raise RuntimeError("Missing environment variables: MONGO_URI, JWT_SECRET_KEY, OPENAI_API_KEY")

# ================================================================
# FASTAPI APP
# ================================================================

app = FastAPI(
    title="AI E-Commerce Strategy Platform",
    version="2.0.0",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

templates    = Jinja2Templates(directory="templates")
oauth2       = OAuth2PasswordBearer(tokenUrl="login")
pwd_context  = CryptContext(schemes=["bcrypt"], deprecated="auto")
openai_client = OpenAI(api_key=OPENAI_KEY)

# ================================================================
# DATABASE
# ================================================================

try:
    mongo_client = MongoClient(
        MONGO_URI,
        tls=True,
        tlsCAFile=certifi.where(),
        serverSelectionTimeoutMS=8000,
    )
    db           = mongo_client["ecommerce_platform"]
    users_col    = db["users"]
    sessions_col = db["sessions"]
    analytics_col = db["analytics"]

    mongo_client.admin.command("ping")
    logger.info("MongoDB connected successfully.")

except Exception as exc:
    logger.critical(f"MongoDB connection failed: {exc}")
    raise exc

# ================================================================
# PASSWORD HELPERS
# ================================================================

def hash_password(plain: str) -> str:
    return pwd_context.hash(plain[:MAX_BCRYPT_LEN])

def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain[:MAX_BCRYPT_LEN], hashed)

def validate_password_strength(password: str) -> bool:
    """Minimum 8 chars, 1 uppercase, 1 digit."""
    return (
        len(password) >= 8
        and any(c.isupper() for c in password)
        and any(c.isdigit() for c in password)
    )

def validate_email(email: str) -> bool:
    return bool(re.match(r"^[\w\.-]+@[\w\.-]+\.\w{2,}$", email))

# ================================================================
# JWT HELPERS
# ================================================================

def create_token(data: dict, hours: int = TOKEN_EXPIRE_H) -> str:
    payload = {**data, "exp": datetime.now(timezone.utc) + timedelta(hours=hours)}
    return jwt.encode(payload, JWT_SECRET, algorithm=ALGORITHM)

def decode_token(token: str) -> Optional[str]:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[ALGORITHM])
        return payload.get("sub")
    except JWTError:
        return None

# ================================================================
# CURRENT USER DEPENDENCY
# ================================================================

async def get_current_user(token: str = Depends(oauth2)) -> dict:
    email = decode_token(token)
    if not email:
        raise HTTPException(status_code=401, detail="Invalid or expired token.")
    user = users_col.find_one({"email": email}, {"_id": 0})
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")
    return user

# ================================================================
# ANALYTICS HELPER
# ================================================================

def log_event(email: str, event: str, meta: dict = {}):
    """Log user activity for internal analytics."""
    analytics_col.insert_one({
        "email": email,
        "event": event,
        "meta": meta,
        "timestamp": datetime.now(timezone.utc),
    })

# ================================================================
# WEBSOCKET MANAGER
# ================================================================

class ConnectionManager:
    def __init__(self):
        self._connections: Dict[str, WebSocket] = {}

    @property
    def active_count(self) -> int:
        return len(self._connections)

    async def connect(self, email: str, ws: WebSocket):
        await ws.accept()
        self._connections[email] = ws
        logger.info(f"WS connected: {email} | Active: {self.active_count}")

    def disconnect(self, email: str):
        self._connections.pop(email, None)
        logger.info(f"WS disconnected: {email} | Active: {self.active_count}")

    async def send(self, email: str, message: str):
        ws = self._connections.get(email)
        if ws:
            await ws.send_text(message)

manager = ConnectionManager()

# ================================================================
# AI TOOL PROMPTS
# ================================================================

def build_prompt(tool: str, **kwargs) -> str:
    """
    Central prompt registry.
    Each tool has a dedicated, production-quality system prompt.
    """

    prompts = {

        # ── 1. Marketing Strategy ────────────────────────────────
        "marketing_strategy": f"""
You are a senior performance marketing strategist with 15+ years
in E-Commerce growth.

Product: {kwargs.get('product_name')}
Price: ${kwargs.get('price')}
Target Audience: {kwargs.get('target_audience')}

Deliver a structured, actionable marketing strategy:

1. AD ANGLES (5 unique psychological hooks)
2. CUSTOMER PERSONAS (3 detailed buyer profiles)
3. IRRESISTIBLE OFFERS (3 conversion-focused bundles or deals)
4. HIGH-CONVERTING HEADLINES (5 — direct response style)
5. MARKETING HOOKS (3 pattern-interrupt openers)
6. OBJECTION HANDLERS (3 common objections + rebuttals)
7. URGENCY TRIGGERS (3 ethical scarcity or urgency tactics)

Be specific. Be direct. No generic advice.
""",

        # ── 2. Product Description ───────────────────────────────
        "product_description": f"""
You are a world-class E-Commerce copywriter.

Product: {kwargs.get('product_name')}
Key Features: {kwargs.get('features')}
Target Buyer: {kwargs.get('target_audience')}
Tone: {kwargs.get('tone', 'professional and persuasive')}

Write:
1. SEO-OPTIMISED TITLE (under 70 characters)
2. SHORT DESCRIPTION (2-3 sentences — for product cards)
3. LONG DESCRIPTION (150-200 words — benefit-led, not feature-led)
4. BULLET POINTS (5 — scannable, benefit-focused)
5. CALL TO ACTION (1 strong sentence)

Do not use filler phrases. Every line must earn its place.
""",

        # ── 3. Ad Copy Generator ─────────────────────────────────
        "ad_copy": f"""
You are a direct response copywriter specialising in paid ads.

Product: {kwargs.get('product_name')}
Platform: {kwargs.get('platform', 'Facebook & Instagram')}
Target Audience: {kwargs.get('target_audience')}
Objective: {kwargs.get('objective', 'Conversions')}

Generate:
1. PRIMARY TEXT (3 variations — under 125 characters each)
2. HEADLINES (5 — under 40 characters each)
3. DESCRIPTIONS (3 — under 30 characters each)
4. VIDEO SCRIPT HOOK (15 seconds — pattern interrupt opening)
5. CAROUSEL COPY (3 slides — headline + one line each)

All copy must be scroll-stopping and conversion-focused.
""",

        # ── 4. Abandoned Cart Email ──────────────────────────────
        "cart_email": f"""
You are an email marketing specialist focused on E-Commerce recovery.

Product: {kwargs.get('product_name')}
Price: ${kwargs.get('price')}
Brand Tone: {kwargs.get('tone', 'warm and professional')}

Write a 3-email abandoned cart sequence:

EMAIL 1 — (Send: 1 hour after abandonment)
Subject line + Body (gentle reminder, no discount)

EMAIL 2 — (Send: 24 hours after abandonment)
Subject line + Body (add social proof + mild urgency)

EMAIL 3 — (Send: 72 hours after abandonment)
Subject line + Body (final offer with incentive)

Each email: under 150 words. Personal. Conversational. No spam language.
""",

        # ── 5. SEO Titles ────────────────────────────────────────
        "seo_titles": f"""
You are an SEO specialist for E-Commerce stores.

Product: {kwargs.get('product_name')}
Category: {kwargs.get('category')}
Target Keywords: {kwargs.get('keywords', 'auto-generate relevant keywords')}
Platform: {kwargs.get('platform', 'Shopify / Google Shopping')}

Generate:
1. PAGE TITLE (5 variations — 50-60 characters, keyword-first)
2. META DESCRIPTION (3 variations — 150-160 characters, includes CTA)
3. ALT TEXT (3 variations — descriptive, keyword-rich)
4. URL SLUG (3 clean options)
5. H1 HEADING (3 variations)

Prioritise search intent. Every title must balance SEO and CTR.
""",

        # ── 6. Customer Review Response ──────────────────────────
        "review_response": f"""
You are a professional customer experience manager for an E-Commerce brand.

Review: {kwargs.get('review')}
Rating: {kwargs.get('rating')} / 5
Brand Tone: {kwargs.get('tone', 'professional, warm, solution-focused')}

Write 3 response variations:
1. SHORT (1-2 sentences — for positive reviews)
2. DETAILED (3-4 sentences — acknowledges, thanks, adds value)
3. RECOVERY (for negative reviews — empathetic, offers solution, no defensiveness)

Each response must feel personal — never copy-paste generic.
""",

        # ── 7. Target Audience Finder ────────────────────────────
        "audience_finder": f"""
You are a consumer psychology expert and market researcher.

Product: {kwargs.get('product_name')}
Price Point: ${kwargs.get('price')}
Category: {kwargs.get('category', 'E-Commerce')}

Identify and profile the ideal buyer:

1. PRIMARY PERSONA (detailed — age, income, psychology, pain points, desires)
2. SECONDARY PERSONA (different segment — same product, different motivation)
3. NEGATIVE PERSONA (who to exclude from targeting and why)
4. BUYING TRIGGERS (what pushes each persona to purchase)
5. CONTENT THAT CONVERTS (what type of content works for each persona)
6. WHERE TO FIND THEM (specific platforms, communities, search terms)
7. MESSAGING THAT LANDS (exact language they use — verbatim)
""",

        # ── 8. Hashtag Generator ─────────────────────────────────
        "hashtags": f"""
You are a social media growth strategist for E-Commerce brands.

Product: {kwargs.get('product_name')}
Category: {kwargs.get('category')}
Platform: {kwargs.get('platform', 'Instagram & TikTok')}
Target Market: {kwargs.get('target_audience')}

Generate:
1. HIGH VOLUME (10 hashtags — 1M+ posts — broad reach)
2. MID VOLUME (10 hashtags — 100K-1M posts — targeted)
3. NICHE (10 hashtags — under 100K posts — community)
4. BRANDED (5 hashtag ideas they can own)
5. TRENDING (5 currently relevant hashtags for this category)

Format as ready-to-copy text blocks. Explain strategy briefly.
""",

        # ── 9. Profit Calculator Insights ────────────────────────
        "profit_insights": f"""
You are a CFO-level E-Commerce financial strategist.

Product: {kwargs.get('product_name')}
Selling Price: ${kwargs.get('selling_price')}
Product Cost: ${kwargs.get('product_cost')}
Shipping Cost: ${kwargs.get('shipping_cost', 0)}
Ad Spend Per Sale: ${kwargs.get('ad_spend', 0)}
Monthly Volume: {kwargs.get('monthly_volume', 100)} units

Calculate and analyse:

1. GROSS MARGIN ($ and %)
2. NET PROFIT PER UNIT (after all costs)
3. MONTHLY NET PROFIT (at given volume)
4. BREAK-EVEN POINT (minimum units to cover fixed costs)
5. SCALE ANALYSIS (profit at 2x, 5x, 10x volume)
6. PRICING RECOMMENDATION (optimal price for margin + competition)
7. COST REDUCTION OPPORTUNITIES (where to improve margins)

Be precise. Use actual numbers. No vague recommendations.
""",

        # ── 10. Store Health Check ───────────────────────────────
        "store_health": f"""
You are a senior Shopify and E-Commerce consultant.

Store URL: {kwargs.get('store_url', 'Not provided')}
Store Type: {kwargs.get('store_type', 'General E-Commerce')}
Monthly Traffic: {kwargs.get('traffic', 'Unknown')}
Conversion Rate: {kwargs.get('conversion_rate', 'Unknown')}
Primary Issues: {kwargs.get('issues', 'Not specified')}

Provide a comprehensive store health audit:

1. CONVERSION KILLERS (top 5 reasons visitors are not buying)
2. TRUST SIGNALS AUDIT (what is missing that reduces credibility)
3. MOBILE EXPERIENCE (critical mobile optimisation issues)
4. PAGE SPEED IMPACT (how speed affects conversions and SEO)
5. PRODUCT PAGE AUDIT (what high-converting product pages include)
6. CHECKOUT OPTIMISATION (friction points and how to remove them)
7. IMMEDIATE ACTION LIST (5 things to fix this week — ranked by impact)

Be direct. Be specific. Prioritise by revenue impact.
""",
    }

    prompt = prompts.get(tool)
    if not prompt:
        raise ValueError(f"Unknown tool: {tool}")
    return prompt.strip()

# ================================================================
# PAGE ROUTES
# ================================================================

@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return templates.TemplateResponse("home.html", {"request": request})

@app.get("/signup-page", response_class=HTMLResponse)
async def signup_page(request: Request):
    return templates.TemplateResponse("signup.html", {"request": request})

@app.get("/login-page", response_class=HTMLResponse)
async def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request):
    return templates.TemplateResponse("dashboard.html", {"request": request})

@app.get("/tools/{tool_name}", response_class=HTMLResponse)
async def tool_page(request: Request, tool_name: str):
    return templates.TemplateResponse("tool.html", {"request": request, "tool": tool_name})

# ================================================================
# AUTH — SIGNUP
# ================================================================

@app.post("/signup", tags=["Auth"])
async def signup(
    username: str = Form(...),
    email:    str = Form(...),
    phone:    str = Form(...),
    password: str = Form(...),
    country:  str = Form(...),
):
    # Validate email
    if not validate_email(email):
        raise HTTPException(status_code=422, detail="Invalid email format.")

    # Validate password strength
    if not validate_password_strength(password):
        raise HTTPException(
            status_code=422,
            detail="Password must be 8+ characters with at least 1 uppercase letter and 1 number."
        )

    # Check duplicates
    if users_col.find_one({"email": email}):
        raise HTTPException(status_code=409, detail="Email already registered.")

    if users_col.find_one({"phone": phone}):
        raise HTTPException(status_code=409, detail="Phone number already in use.")

    user = {
        "username":          username.strip(),
        "email":             email.lower().strip(),
        "phone":             phone.strip(),
        "hashed_password":   hash_password(password),
        "country":           country.strip(),
        "daily_usage":       0,
        "total_usage":       0,
        "usage_reset_date":  datetime.now(timezone.utc).date().isoformat(),
        "last_generations":  [],
        "created_at":        datetime.now(timezone.utc),
        "updated_at":        datetime.now(timezone.utc),
    }

    users_col.insert_one(user)
    token = create_token({"sub": email})
    log_event(email, "signup", {"country": country})
    logger.info(f"New user registered: {email}")

    return {"status": "success", "access_token": token}

# ================================================================
# AUTH — LOGIN
# ================================================================

@app.post("/login", tags=["Auth"])
async def login(
    email:    str = Form(...),
    password: str = Form(...),
):
    user = users_col.find_one({"email": email.lower().strip()}, {"_id": 0})

    if not user or not verify_password(password, user["hashed_password"]):
        raise HTTPException(status_code=401, detail="Invalid email or password.")

    token = create_token({"sub": email})
    log_event(email, "login")

    return {
        "access_token": token,
        "user": {
            "email":       user["email"],
            "username":    user["username"],
            "daily_usage": user.get("daily_usage", 0),
            "limit":       MAX_GENERATIONS,
        }
    }

# ================================================================
# AUTH — FORGOT PASSWORD
# ================================================================

@app.post("/forgot-password", tags=["Auth"])
async def forgot_password(
    email: str = Form(...),
    phone: str = Form(...),
):
    user = users_col.find_one({"email": email, "phone": phone})
    if not user:
        raise HTTPException(status_code=404, detail="No account found with these credentials.")

    code   = str(random.randint(100000, 999999))   # 6-digit code
    expiry = datetime.now(timezone.utc) + timedelta(minutes=RESET_CODE_TTL)

    users_col.update_one(
        {"email": email},
        {"$set": {"reset_code": code, "reset_code_expiry": expiry}}
    )

    # In production — integrate Twilio or similar SMS service here
    logger.info(f"[RESET CODE] {email} → {code}")
    print(f"\n{'='*40}\nSMS TO: {phone}\nCODE: {code}\n{'='*40}\n")

    return {"message": f"Verification code sent to ****{phone[-4:]}"}

# ================================================================
# AUTH — VERIFY RESET CODE
# ================================================================

@app.post("/verify-reset-code", tags=["Auth"])
async def verify_reset_code(
    email: str = Form(...),
    code:  str = Form(...),
):
    user = users_col.find_one({"email": email})
    if not user or user.get("reset_code") != code:
        raise HTTPException(status_code=400, detail="Invalid verification code.")

    expiry = user.get("reset_code_expiry")
    if expiry:
        if expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=timezone.utc)
        if datetime.now(timezone.utc) > expiry:
            raise HTTPException(status_code=400, detail="Code has expired. Request a new one.")

    return {"message": "Verified. You may now reset your password."}

# ================================================================
# AUTH — RESET PASSWORD
# ================================================================

@app.post("/reset-password", tags=["Auth"])
async def reset_password(
    email:        str = Form(...),
    code:         str = Form(...),
    new_password: str = Form(...),
):
    user = users_col.find_one({"email": email})
    if not user or user.get("reset_code") != code:
        raise HTTPException(status_code=400, detail="Unauthorised reset attempt.")

    if not validate_password_strength(new_password):
        raise HTTPException(
            status_code=422,
            detail="Password must be 8+ characters with 1 uppercase and 1 number."
        )

    users_col.update_one(
        {"email": email},
        {
            "$set": {
                "hashed_password": hash_password(new_password),
                "updated_at":      datetime.now(timezone.utc),
            },
            "$unset": {"reset_code": "", "reset_code_expiry": ""}
        }
    )

    log_event(email, "password_reset")
    return {"message": "Password updated successfully."}

# ================================================================
# DAILY USAGE RESET HELPER
# ================================================================

def check_and_reset_daily_usage(user: dict) -> dict:
    """Resets daily usage counter if it is a new calendar day."""
    today = datetime.now(timezone.utc).date().isoformat()
    if user.get("usage_reset_date") != today:
        users_col.update_one(
            {"email": user["email"]},
            {"$set": {"daily_usage": 0, "usage_reset_date": today}}
        )
        user["daily_usage"] = 0
    return user

# ================================================================
# AI GENERATION — REST
# ================================================================

@app.post("/generate/{tool}", tags=["AI Tools"])
async def generate(
    tool:         str,
    request:      Request,
    current_user: dict = Depends(get_current_user),
):
    """
    Universal generation endpoint.
    Accepts any tool name and form data dynamically.
    All tools are free — rate limited to MAX_GENERATIONS per day.
    """
    user = check_and_reset_daily_usage(current_user)

    if user.get("daily_usage", 0) >= MAX_GENERATIONS:
        raise HTTPException(
            status_code=429,
            detail=f"Daily limit of {MAX_GENERATIONS} generations reached. Resets at midnight UTC."
        )

    # Parse form data dynamically
    form_data = await request.form()
    kwargs    = {k: v for k, v in form_data.items()}

    try:
        prompt = build_prompt(tool, **kwargs)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Tool '{tool}' not found.")

    try:
        response = openai_client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {
                    "role": "system",
                    "content": "You are a world-class E-Commerce growth expert. Be specific, actionable, and professional."
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            temperature=0.7,
            max_tokens=2000,
        )
        output = response.choices[0].message.content

    except Exception as exc:
        logger.error(f"OpenAI error for {current_user['email']}: {exc}")
        raise HTTPException(status_code=503, detail="AI service temporarily unavailable.")

    # Update usage and save generation history
    users_col.update_one(
        {"email": current_user["email"]},
        {
            "$inc": {"daily_usage": 1, "total_usage": 1},
            "$push": {
                "last_generations": {
                    "$each": [{
                        "tool":      tool,
                        "inputs":    kwargs,
                        "output":    output,
                        "timestamp": datetime.now(timezone.utc),
                    }],
                    "$slice": -MAX_HISTORY
                }
            }
        }
    )

    log_event(current_user["email"], "generation", {"tool": tool})

    return JSONResponse(content={
        "status":       "success",
        "tool":         tool,
        "output":       output,
        "daily_usage":  user.get("daily_usage", 0) + 1,
        "limit":        MAX_GENERATIONS,
        "remaining":    MAX_GENERATIONS - user.get("daily_usage", 0) - 1,
    })

# ================================================================
# USER PROFILE
# ================================================================

@app.get("/me", tags=["User"])
async def get_profile(current_user: dict = Depends(get_current_user)):
    user = check_and_reset_daily_usage(current_user)
    return {
        "username":     user["username"],
        "email":        user["email"],
        "country":      user.get("country"),
        "daily_usage":  user.get("daily_usage", 0),
        "total_usage":  user.get("total_usage", 0),
        "limit":        MAX_GENERATIONS,
        "remaining":    max(0, MAX_GENERATIONS - user.get("daily_usage", 0)),
        "member_since": user.get("created_at"),
    }

# ================================================================
# GENERATION HISTORY
# ================================================================

@app.get("/history", tags=["User"])
async def get_history(current_user: dict = Depends(get_current_user)):
    user = users_col.find_one(
        {"email": current_user["email"]},
        {"last_generations": 1, "_id": 0}
    )
    generations = user.get("last_generations", [])
    return {
        "count":       len(generations),
        "generations": list(reversed(generations))  # newest first
    }

# ================================================================
# WEBSOCKET — STREAMING GENERATION
# ================================================================

@app.websocket("/ws/generate/{tool}")
async def websocket_generate(
    websocket: WebSocket,
    tool:      str,
    token:     str,
):
    """
    WebSocket endpoint for real-time streaming AI generation.
    Streams token by token for a live typing experience.
    """
    email = decode_token(token)
    if not email:
        await websocket.close(code=1008)
        return

    await manager.connect(email, websocket)

    try:
        while True:
            user = users_col.find_one({"email": email}, {"_id": 0})
            if not user:
                await websocket.close(code=1008)
                return

            user = check_and_reset_daily_usage(user)

            if user.get("daily_usage", 0) >= MAX_GENERATIONS:
                await manager.send(
                    email,
                    f"LIMIT_REACHED: Daily limit of {MAX_GENERATIONS} generations reached. Resets at midnight UTC."
                )
                continue

            data   = await websocket.receive_json()
            kwargs = {k: v for k, v in data.items() if k != "token"}

            try:
                prompt = build_prompt(tool, **kwargs)
            except ValueError:
                await manager.send(email, f"ERROR: Tool '{tool}' not found.")
                continue

            # Stream response token by token
            stream = openai_client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[
                    {
                        "role": "system",
                        "content": "You are a world-class E-Commerce growth expert. Be specific, actionable, and professional."
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                temperature=0.7,
                max_tokens=2000,
                stream=True,
            )

            full_output = ""
            for chunk in stream:
                delta = chunk.choices[0].delta.content
                if delta:
                    full_output += delta
                    await manager.send(email, delta)

            # Signal stream end
            await manager.send(email, "[DONE]")

            # Save to history
            users_col.update_one(
                {"email": email},
                {
                    "$inc": {"daily_usage": 1, "total_usage": 1},
                    "$push": {
                        "last_generations": {
                            "$each": [{
                                "tool":      tool,
                                "inputs":    kwargs,
                                "output":    full_output,
                                "timestamp": datetime.now(timezone.utc),
                            }],
                            "$slice": -MAX_HISTORY
                        }
                    }
                }
            )

            log_event(email, "ws_generation", {"tool": tool})

    except WebSocketDisconnect:
        manager.disconnect(email)
    except Exception as exc:
        logger.error(f"WebSocket error [{email}]: {exc}")
        manager.disconnect(email)

# ================================================================
# HEALTH CHECK
# ================================================================

@app.get("/health", tags=["System"])
async def health():
    return {
        "status":    "running",
        "version":   "2.0.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

# ================================================================
# AVAILABLE TOOLS LIST
# ================================================================

@app.get("/tools", tags=["System"])
async def list_tools():
    return {
        "tools": [
            {
                "id":          "marketing_strategy",
                "name":        "Marketing Strategy Generator",
                "description": "Full conversion-focused marketing strategy for any product.",
                "inputs":      ["product_name", "price", "target_audience"],
            },
            {
                "id":          "product_description",
                "name":        "Product Description Writer",
                "description": "SEO-optimised titles, descriptions, and bullet points.",
                "inputs":      ["product_name", "features", "target_audience", "tone"],
            },
            {
                "id":          "ad_copy",
                "name":        "Ad Copy Generator",
                "description": "Facebook, Instagram, and TikTok ad copy — scroll-stopping.",
                "inputs":      ["product_name", "platform", "target_audience", "objective"],
            },
            {
                "id":          "cart_email",
                "name":        "Abandoned Cart Email Sequence",
                "description": "3-email recovery sequence timed for maximum conversion.",
                "inputs":      ["product_name", "price", "tone"],
            },
            {
                "id":          "seo_titles",
                "name":        "SEO Title Generator",
                "description": "Keyword-optimised titles, meta descriptions, and slugs.",
                "inputs":      ["product_name", "category", "keywords", "platform"],
            },
            {
                "id":          "review_response",
                "name":        "Customer Review Responder",
                "description": "Professional responses for any review — positive or negative.",
                "inputs":      ["review", "rating", "tone"],
            },
            {
                "id":          "audience_finder",
                "name":        "Target Audience Finder",
                "description": "Deep buyer persona profiles with messaging and targeting data.",
                "inputs":      ["product_name", "price", "category"],
            },
            {
                "id":          "hashtags",
                "name":        "Hashtag Generator",
                "description": "Tiered hashtag strategy for Instagram and TikTok.",
                "inputs":      ["product_name", "category", "platform", "target_audience"],
            },
            {
                "id":          "profit_insights",
                "name":        "Profit Margin Analyser",
                "description": "Full margin analysis with scale projections and recommendations.",
                "inputs":      ["product_name", "selling_price", "product_cost", "shipping_cost", "ad_spend", "monthly_volume"],
            },
            {
                "id":          "store_health",
                "name":        "Store Health Checker",
                "description": "Conversion audit — what is killing your sales and how to fix it.",
                "inputs":      ["store_url", "store_type", "traffic", "conversion_rate", "issues"],
            },
        ]
    }
