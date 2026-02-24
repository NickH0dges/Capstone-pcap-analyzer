import os
import sqlite3
from flask_bcrypt import Bcrypt
from flask import Flask

app = Flask(__name__)
bcrypt = Bcrypt(app)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "database.db")

conn = sqlite3.connect(DB_PATH)
c = conn.cursor()

hashed = bcrypt.generate_password_hash("admin123").decode('utf-8')

c.execute(
    "INSERT OR IGNORE INTO users (username, password, role) VALUES (?, ?, ?)",
    ("admin", hashed, "administrator")
)

conn.commit()
conn.close()

print("Admin user created successfully.")