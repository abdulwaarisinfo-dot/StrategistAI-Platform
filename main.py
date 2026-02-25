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
from datetime import datetime, timedelta, timezone
from typing import Dict

# ======================================================
# ------------------- SUBSCRIPTION ---------------------
# ======================================================

subscription = {
    "free": 5,
    "pro": 30,
    "upgrade": 70
}

SUBSCRIPTION_DAYS = 30

# ======================================================
# LOAD ENVIRONMENT VARIABLES
# ======================================================

load_dotenv()

# ======================================================
# LOGGING SETUP
# ======================================================

logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(message)s")
logger = logging.getLogger(__name__)

# ======================================================
# FASTAPI INIT
# ======================================================

app = FastAPI(docs_url= None,
              redoc_url=None,
              openapi_url=None
             )
# Ensure the 'templates' folder exists in your directory structure
templates = Jinja2Templates(directory="templates")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# ======================================================
# PASSWORD HASHING
# ======================================================

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
MAX_BCRYPT_LEN = 72

def hash_password(password: str) -> str:
    return pwd_context.hash(password[:MAX_BCRYPT_LEN])

def verify_password(password: str, hashed: str) -> bool:
    return pwd_context.verify(password[:MAX_BCRYPT_LEN], hashed)

# ======================================================
# ENV VARIABLES
# ======================================================

MONGO_URI = os.getenv("MONGO_URI", "")
JWT_SECRET = os.getenv("JWT_SECRET_KEY", "")
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
    logger.info("MongoDB connected successfully")

except Exception as e:
    logger.error(f"MongoDB connection failed: {e}")
    raise e

# ======================================================
# OPENAI CLIENT
# ======================================================

openai_client = OpenAI(api_key=OPEN_API_KEY)

# ======================================================
# JWT HELPERS
# ======================================================

def create_access_token(data: dict, hours: int = 12):
    payload = data.copy()
    payload["exp"] = datetime.now(timezone.utc) + timedelta(hours=hours)
    return jwt.encode(payload, JWT_SECRET, algorithm=ALGORITHM)

def decode_token(token: str):
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[ALGORITHM])
        return payload.get("sub")
    except JWTError:
        return None

# ======================================================
# SUBSCRIPTION CHECK
# ======================================================

def check_subscription_expiry(user: dict):
    if user.get("subscription") == "free":
        return user

    expiry = user.get("subscription_expiry")

    # Ensure expiry is timezone-aware if it comes from MongoDB as naive
    if expiry and expiry.tzinfo is None:
        expiry = expiry.replace(tzinfo=timezone.utc)

    if expiry and datetime.now(timezone.utc) > expiry:
        users_col.update_one(
            {"email": user["email"]},
            {
                "$set": {
                    "subscription": "free",
                    "subscription_expiry": None
                }
            }
        )
        user["subscription"] = "free"
        user["subscription_expiry"] = None

    return user

# ======================================================
# CURRENT USER
# ======================================================

async def get_current_user(token: str = Depends(oauth2_scheme)):
    email = decode_token(token)
    if not email:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    user = users_col.find_one({"email": email})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

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
        logger.info(f"Current active connections: {self.connections_count}")

    def disconnect(self, email: str):
        if email in self.active_connections:
            del self.active_connections[email]
        self.connections_count = len(self.active_connections)
        logger.info(f"Current active connections: {self.connections_count}")

    async def send_personal_message(self, message: str, email: str):
        websocket = self.active_connections.get(email)
        if websocket:
            await websocket.send_text(message)

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
# FORGOT PASSWORD LOGIC
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
    expiry = datetime.now(timezone.utc) + timedelta(minutes=15)

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
    
    expiry = user.get("reset_code_expiry")
    if expiry and expiry.tzinfo is None:
        expiry = expiry.replace(tzinfo=timezone.utc)

    if datetime.now(timezone.utc) > (expiry or datetime.min.replace(tzinfo=timezone.utc)):
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
                "updated_at": datetime.now(timezone.utc)
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
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
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
# GENERATE (REST)
# ======================================================

@app.post("/generate", tags=["AI"])
async def generate(
    product_name: str = Form(...),
    price: float = Form(...),
    target_audience: str = Form(...),
    current_user: dict = Depends(get_current_user)
):
    plan = current_user.get("subscription", "free")
    usage_limit = subscription.get(plan, 5)

    if current_user.get("usage_count", 0) >= usage_limit:
        raise HTTPException(status_code=403, detail="Usage limit reached. Upgrade plan.")

    auto_prompt = f"""
You are a senior performance marketing strategist.

Product Details:
- Product Name: {product_name}
- Price: {price}
- Target Audience: {target_audience}

Task:
Create a clear, actionable, and conversion-focused marketing strategy.

Generate the following sections:
1. Ad Angles (5)
2. Customer Personas (3)
3. Irresistible Offers (3)
4. High-Converting Headlines (5)
5. Marketing Hooks (3)
"""

    response = openai_client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[
            {"role": "system", "content": "You are a professional marketing strategist."},
            {"role": "user", "content": auto_prompt}
        ],
        temperature=0.7
    )

    ai_output = response.choices[0].message.content

    users_col.update_one(
        {"email": current_user["email"]},
        {
            "$push": {"last_generations": {"$each": [{
                "product_name": product_name,
                "price": price,
                "target_audience": target_audience,
                "output": ai_output,
                "created_at": datetime.now(timezone.utc)
            }], "$slice": -5}},
            "$inc": {"usage_count": 1}
        }
    )

    return JSONResponse(content={"message": "Generation successful", "output": ai_output})

# ======================================================
# WEBSOCKET GENERATION
# ======================================================

@app.websocket("/ws/generate")
async def websocket_generate(websocket: WebSocket, token: str):
    email = decode_token(token)

    if not email:
        await websocket.close(code=1008)
        return

    await manager.connect(email, websocket)

    try:
        while True:
            user = users_col.find_one({"email": email})
            if not user:
                await websocket.close(code=1008)
                return

            user = check_subscription_expiry(user)
            data = await websocket.receive_json()

            plan = user.get("subscription", "free")
            usage_limit = subscription.get(plan, 5)

            if user.get("usage_count", 0) >= usage_limit:
                await manager.send_personal_message(
                    "❌ Usage limit reached. Upgrade plan.",
                    email
                )
                continue

            product_name = data.get("product_name")
            price = data.get("price")
            target_audience = data.get("target_audience")

            # Logic as requested: Prompt simplified for WS version
            auto_prompt = f"Product Name: {product_name}, Audience: {target_audience}. Marketing Strategy."

            response = openai_client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[
                    {"role": "system", "content": "You are a professional marketing strategist."},
                    {"role": "user", "content": auto_prompt}
                ],
                temperature=0.7
            )

            ai_output = response.choices[0].message.content

            users_col.update_one(
                {"email": email},
                {
                    "$push": {
                        "last_generations": {
                            "$each": [{
                                "product_name": product_name,
                                "price": price,
                                "target_audience": target_audience,
                                "output": ai_output,
                                "created_at": datetime.now(timezone.utc)
                            }],
                            "$slice": -5
                        }
                    },
                    "$inc": {"usage_count": 1}
                }
            )

            await manager.send_personal_message(ai_output, email)

    except WebSocketDisconnect:
        manager.disconnect(email)
        logger.info(f"{email} disconnected")
    except Exception as e:
        logger.error(f"WebSocket error for {email}: {e}")
        manager.disconnect(email)
