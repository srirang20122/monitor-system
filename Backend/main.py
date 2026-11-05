import hashlib
import hmac
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone

import jwt
from fastapi import Depends, FastAPI, HTTPException, Response, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, EmailStr, Field
from monitoring import lifespan, router as monitoring_router
from prometheus_fastapi_instrumentator import Instrumentator


DB_PATH = "app.db"
SECRET_KEY = os.environ.get("SECRET_KEY", "change-me-in-production")
ALGORITHM = "HS256"
TOKEN_EXPIRE_MINUTES = 60
PBKDF2_ITERATIONS = 200_000

app = FastAPI(title="Auth API", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:4200"],
    allow_methods=["*"],
    allow_headers=["*"],
)
bearer = HTTPBearer()


# ---------- database ----------
@contextmanager
def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db() -> None:
    with db() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                full_name     TEXT NOT NULL,
                email         TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at    TEXT NOT NULL
            )
            """
        )


init_db()


# ---------- password hashing ----------
def hash_password(password: str) -> str:
    salt = os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ITERATIONS)
    return f"{salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    salt_hex, digest_hex = stored.split("$")
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode(), bytes.fromhex(salt_hex), PBKDF2_ITERATIONS
    )
    return hmac.compare_digest(digest.hex(), digest_hex)


# ---------- tokens ----------
def create_token(user_id: int) -> str:
    expires = datetime.now(timezone.utc) + timedelta(minutes=TOKEN_EXPIRE_MINUTES)
    return jwt.encode({"sub": str(user_id), "exp": expires}, SECRET_KEY, algorithm=ALGORITHM)


def current_user(
    credentials: HTTPAuthorizationCredentials = Depends(bearer),
) -> sqlite3.Row:
    unauthorized = HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid or expired token")
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
    except jwt.PyJWTError:
        raise unauthorized
    with db() as conn:
        user = conn.execute(
            "SELECT id, full_name, email FROM users WHERE id = ?", (int(payload["sub"]),)
        ).fetchone()
    if user is None:
        raise unauthorized
    return user


# ---------- schemas ----------
class RegisterIn(BaseModel):
    full_name: str = Field(min_length=2, max_length=100)
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)


class LoginIn(BaseModel):
    email: EmailStr
    password: str


class UserOut(BaseModel):
    id: int
    full_name: str
    email: str


class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"


# ---------- routes ----------
@app.post("/auth/register", response_model=UserOut, status_code=status.HTTP_201_CREATED)
def register(body: RegisterIn):
    email = body.email.lower()
    with db() as conn:
        exists = conn.execute("SELECT 1 FROM users WHERE email = ?", (email,)).fetchone()
        if exists:
            raise HTTPException(status.HTTP_409_CONFLICT, "Email already registered")
        cur = conn.execute(
            "INSERT INTO users (full_name, email, password_hash, created_at) VALUES (?, ?, ?, ?)",
            (
                body.full_name.strip(),
                email,
                hash_password(body.password),
                datetime.now(timezone.utc).isoformat(),
            ),
        )
        user_id = cur.lastrowid
    return UserOut(id=user_id, full_name=body.full_name.strip(), email=email)


@app.post("/auth/login", response_model=TokenOut)
def login(body: LoginIn):
    with db() as conn:
        user = conn.execute(
            "SELECT id, password_hash FROM users WHERE email = ?", (body.email.lower(),)
        ).fetchone()
    if user is None or not verify_password(body.password, user["password_hash"]):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid email or password")
    return TokenOut(access_token=create_token(user["id"]))


@app.get("/auth/me", response_model=UserOut)
def me(user: sqlite3.Row = Depends(current_user)):
    return UserOut(id=user["id"], full_name=user["full_name"], email=user["email"])


@app.post("/auth/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(_: sqlite3.Row = Depends(current_user)):
    # JWTs are stateless: the client discards the token. This endpoint only
    # confirms the token was valid, and is the place to add a deny-list later.
    return Response(status_code=status.HTTP_204_NO_CONTENT)

# All monitoring routes require a valid login token.
app.include_router(monitoring_router, dependencies=[Depends(current_user)])

Instrumentator().instrument(app).expose(app)