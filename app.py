from flask import Flask, render_template, request, redirect, session
from flask_bcrypt import Bcrypt
import sqlite3

app = Flask(__name__)
app.secret_key = "my_secret_key"

bcrypt = Bcrypt(app)

conn = sqlite3.connect("users.db")
conn.execute("""
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT,
    password TEXT
)
""")
conn.close()


@app.route("/")
def index():
    if "username" in session:
        return render_template("home.html", username=session["username"])
    else:
        return redirect("/login")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")

        conn = sqlite3.connect("users.db")
        conn.execute(
            "INSERT INTO users (username, password) VALUES (?, ?)",
            (username, hashed_password)
        )
        conn.commit()
        conn.close()

        return redirect("/login")

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        conn = sqlite3.connect("users.db")
        cursor = conn.cursor()

        cursor.execute(
            "SELECT * FROM users WHERE username = ?",
            (username,)
        )

        user = cursor.fetchone()
        conn.close()

        if user:
            stored_password = user[2]

            if bcrypt.check_password_hash(stored_password, password):
                session["username"] = username
                return redirect("/")
            else:
                return "Wrong password"
        else:
            return "User not found"

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.pop("username", None)
    return redirect("/login")


if __name__ == "__main__":
    app.run(debug=True)
