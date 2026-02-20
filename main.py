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
from datetime import datetime, timedelta
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

app = FastAPI()
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
JWT_SECRET = os.getenv("JWT_SECRET_KEY", "super-secret-key")
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
    payload["exp"] = datetime.utcnow() + timedelta(hours=hours)
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

    if expiry and datetime.utcnow() > expiry:
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
        self.connections_count: int = 0  # <-- Added connection counter

    async def connect(self, email: str, websocket: WebSocket):
        await websocket.accept()
        self.active_connections[email] = websocket
        self.connections_count = len(self.active_connections)
        logger.info(f"Current active connections: {self.connections_count}")  # <-- Log count

    def disconnect(self, email: str):
        if email in self.active_connections:
            del self.active_connections[email]
        self.connections_count = len(self.active_connections)
        logger.info(f"Current active connections: {self.connections_count}")  # <-- Log count

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
# SIGNUP (REST)
# ======================================================

@app.post("/signup", tags=["Auth"])
async def signup(
    username: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    country: str = Form(...)
):
    if users_col.find_one({"email": email}):
        raise HTTPException(status_code=400, detail="User already exists")

    new_user = {
        "username": username,
        "email": email,
        "hashed_password": hash_password(password),
        "subscription": "free",
        "subscription_expiry": None,
        "created_at": datetime.utcnow(),
        "country": country,
        "last_generations": [],
        "usage_count": 0
    }

    users_col.insert_one(new_user)

    token = create_access_token({"sub": email})

    return {
        "message": "User registered successfully",
        "access_token": token,
        "token_type": "bearer"
    }

# ======================================================
# LOGIN (REST)
# ======================================================

@app.post("/login", tags=["Auth"])
async def login(email: str = Form(...), password: str = Form(...)):
    user = users_col.find_one({"email": email})

    if not user or not verify_password(password, user["hashed_password"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    user = check_subscription_expiry(user)

    token = create_access_token({"sub": email})

    return {
        "access_token": token,
        "token_type": "bearer",
        "last_generations": user.get("last_generations", []),
        "subscription": user.get("subscription"),
        "country": user.get("country")
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
   - Each angle must target a different psychological trigger.

2. Customer Personas (3)
   - Include age range, main pain point, and buying motivation.

3. Irresistible Offers (3)
   - Use urgency, bonuses, or guarantees.

4. High-Converting Headlines (5)
   - Short, bold, and scroll-stopping.

5. Marketing Hooks (3)
   - Strong opening lines for ads or landing pages.

Rules:
- Be practical, not theoretical.
- Avoid generic marketing buzzwords.
- Focus on real conversions.
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
                "created_at": datetime.utcnow()
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

            auto_prompt = f"""
            Product Name: {product_name}
           Price: {price}
           Target Audience: {target_audience}
           Generate complete marketing strategy.
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
                {"email": email},
                {
                    "$push": {
                        "last_generations": {
                            "$each": [{
                                "product_name": product_name,
                                "price": price,
                                "target_audience": target_audience,
                                "output": ai_output,
                                "created_at": datetime.utcnow()
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