from fastapi import FastAPI, HTTPException, Depends, Form, Request, WebSocket, WebSocketDisconnect
from fastapi.security import OAuth2PasswordBearer
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates

from jose import jwt, JWTError
from passlib.context import CryptContext
from dotenv import load_dotenv

from pymongo import MongoClient
from openai import OpenAI
import certifi
import os
import logging
import random
from datetime import datetime, timedelta
from typing import Dict, List, Optional

# ======================================================
# ------------------- SUBSCRIPTION ---------------------
# ======================================================

# Dictionary to manage tiered usage limits for users
subscription_tiers = {
    "free": 5,
    "pro": 30,
    "upgrade": 70
}

# Standard duration for paid subscriptions in days
SUBSCRIPTION_DAYS = 30

# ======================================================
# LOAD ENVIRONMENT VARIABLES
# ======================================================

load_dotenv()

# ======================================================
# LOGGING SETUP
# ======================================================

logging.basicConfig(
    level=logging.INFO, 
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s"
)
logger = logging.getLogger(__name__)

# ======================================================
# FASTAPI INIT
# ======================================================

app = FastAPI(title="AI Marketing Strategist API", version="1.1.0")
templates = Jinja2Templates(directory="templates")

# Security scheme for JWT Bearer tokens
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# ======================================================
# PASSWORD HASHING
# ======================================================

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
MAX_BCRYPT_LEN = 72

def hash_password(password: str) -> str:
    """Hashes a plain-text password using bcrypt."""
    return pwd_context.hash(password[:MAX_BCRYPT_LEN])

def verify_password(password: str, hashed: str) -> bool:
    """Verifies a plain-text password against a stored hash."""
    return pwd_context.verify(password[:MAX_BCRYPT_LEN], hashed)

# ======================================================
# ENV VARIABLES & CONFIGURATION
# ======================================================

MONGO_URI = os.getenv("MONGO_URI", "")
JWT_SECRET = os.getenv("JWT_SECRET_KEY", "super-secret-key-change-in-production")
OPEN_API_KEY = os.getenv("OPEN_API_KEY", "")
ALGORITHM = "HS256"

# ======================================================
# DATABASE CONNECTION
# ======================================================

try:
    client = MongoClient(
        MONGO_URI,
        tls=True,
        tlsCAFile=certifi.where(),
        serverSelectionTimeoutMS=10000
    )

    db = client["Data"]
    users_col = db["users"]

    client.admin.command("ping")
    logger.info("Connection to MongoDB established successfully.")

except Exception as e:
    logger.critical(f"FATAL: MongoDB connection failed: {e}")
    raise SystemExit("Exiting: Database unavailable.")

# ======================================================
# OPENAI CLIENT
# ======================================================

openai_client = OpenAI(api_key=OPEN_API_KEY)

# ======================================================
# JWT HELPERS
# ======================================================

def create_access_token(data: dict, hours: int = 12):
    payload = data.copy()
    payload["exp"] = datetime.utcnow() + timedelta(hours=hours)
    payload["iat"] = datetime.utcnow()
    return jwt.encode(payload, JWT_SECRET, algorithm=ALGORITHM)

def decode_token(token: str):
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[ALGORITHM])
        return payload.get("sub")
    except JWTError as e:
        logger.warning(f"Token decoding failed: {e}")
        return None

# ======================================================
# SUBSCRIPTION & USAGE LOGIC
# ======================================================

def check_subscription_expiry(user: dict):
    if user.get("subscription") == "free":
        return user

    expiry = user.get("subscription_expiry")
    if expiry and datetime.utcnow() > expiry:
        logger.info(f"Subscription expired for user: {user['email']}. Reverting to free.")
        users_col.update_one(
            {"email": user["email"]},
            {
                "$set": {
                    "subscription": "free",
                    "subscription_expiry": None,
                    "updated_at": datetime.utcnow()
                }
            }
        )
        user["subscription"] = "free"
        user["subscription_expiry"] = None
    return user

async def get_current_user(token: str = Depends(oauth2_scheme)):
    email = decode_token(token)
    if not email:
        raise HTTPException(status_code=401, detail="Invalid session or expired token")

    user = users_col.find_one({"email": email})
    if not user:
        raise HTTPException(status_code=404, detail="Account not found")

    user = check_subscription_expiry(user)
    return user

# ======================================================
# WEBSOCKET CONNECTION MANAGER
# ======================================================

class ConnectionManager:
    def __init__(self):
        self.active_connections: Dict[str, WebSocket] = {}
        self.connections_count: int = 0

    async def connect(self, email: str, websocket: WebSocket):
        await websocket.accept()
        self.active_connections[email] = websocket
        self.connections_count = len(self.active_connections)
        logger.info(f"Active WS connection: {email}. Total: {self.connections_count}")

    def disconnect(self, email: str):
        if email in self.active_connections:
            del self.active_connections[email]
        self.connections_count = len(self.active_connections)
        logger.info(f"WS disconnect: {email}. Remaining: {self.connections_count}")

    async def send_personal_message(self, message: str, email: str):
        websocket = self.active_connections.get(email)
        if websocket:
            try:
                await websocket.send_text(message)
            except Exception as e:
                logger.error(f"Error sending WS message to {email}: {e}")

manager = ConnectionManager()

# ======================================================
# PAGE ROUTES
# ======================================================

@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return templates.TemplateResponse("home.html", {"request": request})

@app.get("/signup-page", response_class=HTMLResponse)
async def signup_page(request: Request):
    return templates.TemplateResponse("signup.html", {"request": request})

@app.get("/login-page", response_class=HTMLResponse)
async def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

@app.get("/page", response_class=HTMLResponse)
async def main_page(request: Request):
    return templates.TemplateResponse("page.html", {"request": request})

# ======================================================
# FORGOT PASSWORD & PHONE VERIFICATION LOGIC
# ======================================================

@app.post("/forgot-password-request", tags=["Auth"])
async def forgot_password_request(
    email: str = Form(...),
    phone: str = Form(...) 
):
    """Requests a password reset code. Validates Email + Phone combo."""
    user = users_col.find_one({"email": email, "phone": phone})
    if not user:
        raise HTTPException(status_code=404, detail="Credentials do not match our records.")

    reset_code = str(random.randint(1000, 9999))
    expiry = datetime.utcnow() + timedelta(minutes=15)

    # SIMULATED SMS LOGGING
    print("\n" + "="*40)
    print(f"SMS SENT TO: {phone}")
    print(f"MESSAGE: Your AI Strategist reset code is: {reset_code}")
    print("="*40 + "\n")
    
    logger.info(f"SECURITY: Generated reset code {reset_code} for {email}")

    users_col.update_one(
        {"email": email},
        {
            "$set": {
                "reset_code": reset_code,
                "reset_code_expiry": expiry
            }
        }
    )

    return {"message": f"Verification code sent to ****{phone[-4:]}", "code_preview": reset_code}

@app.post("/verify-reset-code", tags=["Auth"])
async def verify_reset_code(email: str = Form(...), code: str = Form(...)):
    user = users_col.find_one({"email": email})
    if not user or user.get("reset_code") != code:
        raise HTTPException(status_code=400, detail="Invalid verification code")
    
    if datetime.utcnow() > user.get("reset_code_expiry", datetime.min):
        raise HTTPException(status_code=400, detail="Verification code has expired")

    return {"message": "Verified. Proceed to reset password."}

@app.post("/reset-password", tags=["Auth"])
async def reset_password(
    email: str = Form(...), 
    code: str = Form(...), 
    new_password: str = Form(...)
):
    user = users_col.find_one({"email": email})
    if not user or user.get("reset_code") != code:
        raise HTTPException(status_code=400, detail="Reset failed: Unauthorized session")

    users_col.update_one(
        {"email": email},
        {
            "$set": {
                "hashed_password": hash_password(new_password),
                "updated_at": datetime.utcnow()
            },
            "$unset": {
                "reset_code": "", 
                "reset_code_expiry": ""
            }
        }
    )
    return {"message": "Password updated successfully."}

# ======================================================
# SIGNUP & LOGIN
# ======================================================

@app.post("/signup", tags=["Auth"])
async def signup(
    username: str = Form(...),
    email: str = Form(...),
    phone: str = Form(...),
    password: str = Form(...),
    country: str = Form(...)
):
    if users_col.find_one({"email": email}):
        raise HTTPException(status_code=400, detail="Email already registered")
    
    if users_col.find_one({"phone": phone}):
        raise HTTPException(status_code=400, detail="Phone number already in use")

    new_user = {
        "username": username,
        "email": email,
        "phone": phone,
        "hashed_password": hash_password(password),
        "subscription": "free",
        "subscription_expiry": None,
        "created_at": datetime.utcnow(),
        "updated_at": datetime.utcnow(),
        "country": country,
        "last_generations": [],
        "usage_count": 0
    }

    users_col.insert_one(new_user)
    token = create_access_token({"sub": email})
    return {"status": "success", "access_token": token}

@app.post("/login", tags=["Auth"])
async def login(email: str = Form(...), password: str = Form(...)):
    user = users_col.find_one({"email": email})
    if not user or not verify_password(password, user["hashed_password"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    user = check_subscription_expiry(user)
    token = create_access_token({"sub": email})
    
    return {
        "access_token": token,
        "user_profile": {
            "email": user["email"],
            "username": user["username"],
            "subscription": user["subscription"],
            "phone": user.get("phone")
        }
    }

# ======================================================
# GENERATE (PRESERVED LOGIC)
# ======================================================

@app.post("/generate", tags=["AI"])
async def generate(
    product_name: str = Form(...),
    price: float = Form(...),
    target_audience: str = Form(...),
    current_user: dict = Depends(get_current_user)
):
    plan = current_user.get("subscription", "free")
    usage_limit = subscription_tiers.get(plan, 5)
    current_usage = current_user.get("usage_count", 0)

    if current_usage >= usage_limit:
        raise HTTPException(status_code=403, detail="Limit reached. Please upgrade.")

    prompt = f"Senior Strategist: Create conversion plan for {product_name} at {price} for {target_audience}."

    try:
        response = openai_client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": prompt}]
        )
        ai_output = response.choices[0].message.content

        users_col.update_one(
            {"email": current_user["email"]},
            {
                "$push": {"last_generations": {"$each": [{"product": product_name, "output": ai_output}], "$slice": -10}},
                "$inc": {"usage_count": 1}
            }
        )
        return {"output": ai_output, "remaining": usage_limit - (current_usage + 1)}
    except Exception as e:
        logger.error(f"AI Error: {e}")
        raise HTTPException(status_code=500, detail="AI Service unavailable")

# ======================================================
# WEBSOCKET GENERATION
# ======================================================

@app.websocket("/ws/generate")
async def websocket_generate(websocket: WebSocket, token: str):
    """Real-time generation via WebSocket for interactive experiences."""
    email = decode_token(token)

    if not email:
        logger.warning("Unauthenticated WS attempt")
        await websocket.close(code=1008)
        return

    await manager.connect(email, websocket)

    try:
        while True:
            # Refresh user data each loop to check limits
            user = users_col.find_one({"email": email})
            if not user:
                await websocket.close(code=1008)
                return

            user = check_subscription_expiry(user)
            
            # Wait for user to send generation parameters
            data = await websocket.receive_json()

            plan = user.get("subscription", "free")
            limit = subscription_tiers.get(plan, 5)
            count = user.get("usage_count", 0)

            if count >= limit:
                await manager.send_personal_message(
                    "ERROR: ❌ Usage limit reached. Upgrade to Pro for more generations.",
                    email
                )
                continue

            # Data Extraction
            product_name = data.get("product_name", "Unknown Product")
            price = data.get("price", 0)
            audience = data.get("target_audience", "General")

            # Notification to user
            await manager.send_personal_message("STATUS: ⏳ Analyzing market data...", email)

            # OpenAI Call
            resp = openai_client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[
                    {"role": "system", "content": "You are a professional marketing strategist."},
                    {"role": "user", "content": f"Strategy for {product_name} targeting {audience} at price {price}"}
                ],
                temperature=0.7
            )

            ai_output = resp.choices[0].message.content

            # Persist data
            users_col.update_one(
                {"email": email},
                {
                    "$push": {
                        "last_generations": {
                            "$each": [{
                                "product_name": product_name,
                                "price": price,
                                "target_audience": audience,
                                "output": ai_output,
                                "created_at": datetime.utcnow()
                            }],
                            "$slice": -10
                        }
                    },
                    "$inc": {"usage_count": 1}
                }
            )

            # Stream result back
            await manager.send_personal_message(ai_output, email)
            await manager.send_personal_message(f"STATUS: ✅ Done! Used {count+1}/{limit}", email)

    except WebSocketDisconnect:
        manager.disconnect(email)
    except Exception as e:
        logger.error(f"WS Runtime Error for {email}: {e}")
        manager.disconnect(email)

# ======================================================
# HEALTH CHECK & INFO
# ======================================================

@app.get("/health", tags=["System"])
async def health_check():
    """Returns the current status of the API and DB connection."""
    try:
        client.admin.command("ping")
        db_status = "Online"
    except:
        db_status = "Offline"
        
    return {
        "status": "active",
        "database": db_status,
        "timestamp": datetime.utcnow(),
        "active_ws": manager.connections_count
    }

# ======================================================
# APP ENTRY POINT
# ======================================================

