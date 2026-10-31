
from datetime import datetime, timedelta, timezone
import sqlite3
import secrets

import bcrypt
import jwt
from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, Field

app = FastAPI(title="JWT Authentication API")

# For this learning project only. Keep your real secret private.
SECRET_KEY = secrets.token_hex(32)
ALGORITHM = "HS256"
TOKEN_EXPIRE_MINUTES = 30

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")


# ---------- DATABASE ----------

def get_db():
    conn = sqlite3.connect("users.db")
    conn.row_factory = sqlite3.Row
    return conn


def setup_database():
    with get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS items (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                owner_id INTEGER NOT NULL,
                FOREIGN KEY (owner_id) REFERENCES users(id)
            )
        """)


setup_database()


# ---------- REQUEST VALIDATION ----------

class UserCreate(BaseModel):
    username: str = Field(min_length=3, max_length=50)
    password: str = Field(min_length=8, max_length=72)


class ItemCreate(BaseModel):
    title: str = Field(min_length=1, max_length=100)
    description: str = Field(max_length=500)


# ---------- JWT AND PASSWORD HELPERS ----------

def create_token(username: str):
    expiry = datetime.now(timezone.utc) + timedelta(
        minutes=TOKEN_EXPIRE_MINUTES
    )
    return jwt.encode(
        {"sub": username, "exp": expiry},
        SECRET_KEY,
        algorithm=ALGORITHM
    )


def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(
            token, SECRET_KEY, algorithms=[ALGORITHM]
        )
        username = payload.get("sub")

        if not username:
            raise HTTPException(
                status_code=401, detail="Invalid token"
            )
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=401, detail="Invalid or expired token"
        )

    with get_db() as conn:
        user = conn.execute(
            "SELECT * FROM users WHERE username = ?",
            (username,)
        ).fetchone()

    if user is None:
        raise HTTPException(status_code=401, detail="User not found")

    return user


# ---------- REGISTER AND LOGIN ----------

@app.post("/register", status_code=201)
def register(data: UserCreate):
    hashed_password = bcrypt.hashpw(
        data.password.encode("utf-8"),
        bcrypt.gensalt()
    ).decode("utf-8")

    try:
        with get_db() as conn:
            conn.execute(
                "INSERT INTO users (username, password) VALUES (?, ?)",
                (data.username, hashed_password)
            )
    except sqlite3.IntegrityError:
        raise HTTPException(
            status_code=400, detail="Username already exists"
        )

    return {"message": "User registered successfully"}


@app.post("/login")
def login(form: OAuth2PasswordRequestForm = Depends()):
    with get_db() as conn:
        user = conn.execute(
            "SELECT * FROM users WHERE username = ?",
            (form.username,)
        ).fetchone()

    if user is None or not bcrypt.checkpw(
        form.password.encode("utf-8"),
        user["password"].encode("utf-8")
    ):
        raise HTTPException(
            status_code=401, detail="Incorrect username or password"
        )

    return {
        "access_token": create_token(user["username"]),
        "token_type": "bearer"
    }


# ---------- CREATE ITEM ----------

@app.post("/items", status_code=201)
def create_item(
    item: ItemCreate,
    user=Depends(get_current_user)
):
    with get_db() as conn:
        cursor = conn.execute(
            """INSERT INTO items (title, description, owner_id)
               VALUES (?, ?, ?)""",
            (item.title, item.description, user["id"])
        )
        item_id = cursor.lastrowid

    return {"message": "Item created", "id": item_id}


# ---------- READ ITEMS ----------

@app.get("/items")
def read_items(user=Depends(get_current_user)):
    with get_db() as conn:
        rows = conn.execute(
            """SELECT id, title, description FROM items
               WHERE owner_id = ?""",
            (user["id"],)
        ).fetchall()

    return [dict(row) for row in rows]


# ---------- UPDATE ITEM ----------

@app.put("/items/{item_id}")
def update_item(
    item_id: int,
    item: ItemCreate,
    user=Depends(get_current_user)
):
    with get_db() as conn:
        cursor = conn.execute(
            """UPDATE items SET title = ?, description = ?
               WHERE id = ? AND owner_id = ?""",
            (item.title, item.description, item_id, user["id"])
        )

        if cursor.rowcount == 0:
            raise HTTPException(
                status_code=404, detail="Item not found"
            )

    return {"message": "Item updated successfully"}


# ---------- DELETE ITEM ----------

@app.delete("/items/{item_id}")
def delete_item(item_id: int, user=Depends(get_current_user)):
    with get_db() as conn:
        cursor = conn.execute(
            "DELETE FROM items WHERE id = ? AND owner_id = ?",
            (item_id, user["id"])
        )

        if cursor.rowcount == 0:
            raise HTTPException(
                status_code=404, detail="Item not found"
            )

    return {"message": "Item deleted successfully"}


@app.get("/")
def home():
    return {"message": "FastAPI JWT API is running"}
