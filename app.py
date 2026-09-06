from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3
import re
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

# ---------------- FLASK APP ----------------

app = Flask(__name__)
app.secret_key = "stationery_shop_secret_key"

DATABASE = "stationery.db"


# ---------------- DATABASE CONNECTION ----------------

def get_db():

    connection = sqlite3.connect(DATABASE)

    connection.row_factory = sqlite3.Row

    return connection


# ---------------- CREATE DATABASE ----------------

def create_database():

    db = get_db()

    # ---------------- USERS TABLE ----------------

    db.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    """)

    # ---------------- PRODUCTS TABLE ----------------

    db.execute("""
        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            category TEXT NOT NULL,
            price REAL NOT NULL,
            stock INTEGER NOT NULL,
            unit TEXT NOT NULL,

            FOREIGN KEY (user_id)
            REFERENCES users(id)
        )
    """)

    # ---------------- SALES TABLE ----------------

    db.execute("""
        CREATE TABLE IF NOT EXISTS sales (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            bill_no TEXT NOT NULL,
            customer_name TEXT NOT NULL,
            total REAL NOT NULL,
            sale_date TEXT NOT NULL,

            FOREIGN KEY (user_id)
            REFERENCES users(id)
        )
    """)

    # ---------------- SALE ITEMS TABLE ----------------

    db.execute("""
        CREATE TABLE IF NOT EXISTS sale_items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            sale_id INTEGER NOT NULL,
            product_id INTEGER NOT NULL,
            quantity INTEGER NOT NULL,
            price REAL NOT NULL,
            subtotal REAL NOT NULL,

            FOREIGN KEY (user_id)
            REFERENCES users(id),

            FOREIGN KEY (sale_id)
            REFERENCES sales(id),

            FOREIGN KEY (product_id)
            REFERENCES products(id)
        )
    """)

    # ---------------- SETTINGS TABLE ----------------

    db.execute("""
        CREATE TABLE IF NOT EXISTS settings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER UNIQUE NOT NULL,
            shop_name TEXT NOT NULL,
            owner_name TEXT NOT NULL,

            FOREIGN KEY (user_id)
            REFERENCES users(id)
        )
    """)

    # ---------------- DEFAULT ADMIN ACCOUNT ----------------

    user = db.execute(
        "SELECT * FROM users WHERE username = ?",
        ("admin",)
    ).fetchone()

    if user is None:

        hashed_password = generate_password_hash(
            "Admin@123"
        )

        db.execute(
            """
            INSERT INTO users
            (username, password)
            VALUES (?, ?)
            """,
            ("admin", hashed_password)
        )

    db.commit()
    db.close()


# ---------------- LOGIN REQUIRED ----------------

def login_required():

    return "user_id" in session


# ---------------- PASSWORD VALIDATION ----------------

def valid_password(password):

    # Minimum 8 characters
    if len(password) < 8:

        return False, (
            "Password must contain at least 8 characters."
        )

    # Uppercase letter
    if not re.search(r"[A-Z]", password):

        return False, (
            "Password must contain at least one uppercase letter."
        )

    # Lowercase letter
    if not re.search(r"[a-z]", password):

        return False, (
            "Password must contain at least one lowercase letter."
        )

    # Number
    if not re.search(r"[0-9]", password):

        return False, (
            "Password must contain at least one number."
        )

    # Special symbol
    if not re.search(r"[^A-Za-z0-9]", password):

        return False, (
            "Password must contain at least one special symbol."
        )

    return True, ""


# ---------------- CREATE USER SETTINGS ----------------

def create_default_settings(user_id, username):

    db = get_db()

    setting = db.execute(
        """
        SELECT * FROM settings
        WHERE user_id = ?
        """,
        (user_id,)
    ).fetchone()

    if setting is None:

        db.execute(
            """
            INSERT INTO settings
            (user_id, shop_name, owner_name)
            VALUES (?, ?, ?)
            """,
            (
                user_id,
                "Stationery Shop",
                username
            )
        )

        db.commit()

    db.close()


# ---------------- HOME ----------------

@app.route("/")
def home():

    if login_required():

        return redirect(
            url_for("dashboard")
        )

    return redirect(
        url_for("login")
    )


# ---------------- REGISTER ----------------

@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        username = request.form["username"].strip()

        password = request.form["password"]

        confirm_password = request.form[
            "confirm_password"
        ]

        # Check empty username
        if not username:

            flash("Username cannot be empty!")

            return redirect(
                url_for("register")
            )

        # Check passwords match
        if password != confirm_password:

            flash("Passwords do not match!")

            return redirect(
                url_for("register")
            )

        # Check password rules
        is_valid, message = valid_password(
            password
        )

        if not is_valid:

            flash(message)

            return redirect(
                url_for("register")
            )

        db = get_db()

        # Check username
        existing_user = db.execute(
            """
            SELECT * FROM users
            WHERE username = ?
            """,
            (username,)
        ).fetchone()

        if existing_user:

            db.close()

            flash(
                "Username already exists!"
            )

            return redirect(
                url_for("register")
            )

        # Hash password
        hashed_password = generate_password_hash(
            password
        )

        # Add user
        cursor = db.execute(
            """
            INSERT INTO users
            (username, password)
            VALUES (?, ?)
            """,
            (
                username,
                hashed_password
            )
        )

        # Get new user ID
        user_id = cursor.lastrowid

        # Create separate settings
        db.execute(
            """
            INSERT INTO settings
            (user_id, shop_name, owner_name)
            VALUES (?, ?, ?)
            """,
            (
                user_id,
                "Stationery Shop",
                username
            )
        )

        db.commit()

        db.close()

        flash(
            "Registration successful! Please login."
        )

        return redirect(
            url_for("login")
        )

    return render_template(
        "register.html"
    )


# ---------------- LOGIN ----------------

@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        username = request.form[
            "username"
        ].strip()

        password = request.form[
            "password"
        ]

        db = get_db()

        user = db.execute(
            """
            SELECT * FROM users
            WHERE username = ?
            """,
            (username,)
        ).fetchone()

        db.close()

        if user and check_password_hash(
            user["password"],
            password
        ):

            # Store current user information

            session["user_id"] = user["id"]

            session["username"] = user[
                "username"
            ]

            # Create settings if missing
            create_default_settings(
                user["id"],
                user["username"]
            )

            return redirect(
                url_for("dashboard")
            )

        flash(
            "Invalid username or password!"
        )

    return render_template(
        "login.html"
    )


# ---------------- DASHBOARD ----------------

@app.route("/dashboard")
def dashboard():

    if not login_required():

        return redirect(
            url_for("login")
        )

    user_id = session["user_id"]

    db = get_db()

    # Total products for current user

    total_products = db.execute(
        """
        SELECT COUNT(*) AS total
        FROM products
        WHERE user_id = ?
        """,
        (user_id,)
    ).fetchone()["total"]

    # Total sales for current user

    total_sales = db.execute(
        """
        SELECT COALESCE(SUM(total), 0)
        AS total

        FROM sales

        WHERE user_id = ?
        """,
        (user_id,)
    ).fetchone()["total"]

    # Total bills for current user

    total_bills = db.execute(
        """
        SELECT COUNT(*) AS total

        FROM sales

        WHERE user_id = ?
        """,
        (user_id,)
    ).fetchone()["total"]

    # Low stock items for current user

    low_stock = db.execute(
        """
        SELECT COUNT(*) AS total

        FROM products

        WHERE stock <= 5
        AND user_id = ?
        """,
        (user_id,)
    ).fetchone()["total"]

    # Low stock product list

    low_stock_products = db.execute(
        """
        SELECT *

        FROM products

        WHERE stock <= 5
        AND user_id = ?

        ORDER BY stock ASC
        """,
        (user_id,)
    ).fetchall()

    db.close()

    return render_template(
        "dashboard.html",

        total_products=total_products,

        total_sales=total_sales,

        total_bills=total_bills,

        low_stock=low_stock,

        low_stock_products=low_stock_products
    )


# ---------------- PRODUCTS ----------------

@app.route(
    "/products",
    methods=["GET", "POST"]
)
def products():

    if not login_required():

        return redirect(
            url_for("login")
        )

    user_id = session["user_id"]

    db = get_db()

    # Add new product

    if request.method == "POST":

        name = request.form["name"]

        category = request.form["category"]

        price = request.form["price"]

        stock = request.form["stock"]

        unit = request.form["unit"]

        db.execute(
            """
            INSERT INTO products

            (
                user_id,
                name,
                category,
                price,
                stock,
                unit
            )

            VALUES (?, ?, ?, ?, ?, ?)
            """,

            (
                user_id,
                name,
                category,
                price,
                stock,
                unit
            )
        )

        db.commit()

        flash(
            "Product added successfully!"
        )

        db.close()

        return redirect(
            url_for("products")
        )

    # Show products ONLY for current user

    products_data = db.execute(
        """
        SELECT *

        FROM products

        WHERE user_id = ?

        ORDER BY id DESC
        """,
        (user_id,)
    ).fetchall()

    db.close()

    return render_template(
        "products.html",
        products=products_data
    )


# ---------------- DELETE PRODUCT ----------------

@app.route(
    "/delete_product/<int:id>"
)
def delete_product(id):

    if not login_required():

        return redirect(
            url_for("login")
        )

    user_id = session["user_id"]

    db = get_db()

    # Delete only the current user's product

    db.execute(
        """
        DELETE FROM products

        WHERE id = ?
        AND user_id = ?
        """,
        (
            id,
            user_id
        )
    )

    db.commit()

    db.close()

    flash(
        "Product deleted successfully!"
    )

    return redirect(
        url_for("products")
    )


# ---------------- BILLING ----------------

@app.route(
    "/billing",
    methods=["GET", "POST"]
)
def billing():

    if not login_required():

        return redirect(
            url_for("login")
        )

    user_id = session["user_id"]

    db = get_db()

    # Show products only for current user

    products_data = db.execute(
        """
        SELECT *

        FROM products

        WHERE stock > 0
        AND user_id = ?

        ORDER BY name
        """,
        (user_id,)
    ).fetchall()

    # Create bill

    if request.method == "POST":

        customer_name = request.form[
            "customer_name"
        ]

        product_id = int(
            request.form["product_id"]
        )

        quantity = int(
            request.form["quantity"]
        )

        # Get product only from current user

        product = db.execute(
            """
            SELECT *

            FROM products

            WHERE id = ?
            AND user_id = ?
            """,
            (
                product_id,
                user_id
            )
        ).fetchone()

        if product is None:

            db.close()

            flash(
                "Product not found!"
            )

            return redirect(
                url_for("billing")
            )

        if quantity <= 0:

            db.close()

            flash(
                "Quantity must be greater than 0!"
            )

            return redirect(
                url_for("billing")
            )

        if quantity > product["stock"]:

            db.close()

            flash(
                "Not enough stock!"
            )

            return redirect(
                url_for("billing")
            )

        # Calculate total

        subtotal = (
            product["price"]
            * quantity
        )

        # Create bill number

        bill_no = (
            "B"
            + datetime.now().strftime(
                "%Y%m%d%H%M%S%f"
            )
        )

        sale_date = datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        )

        # Insert sale

        cursor = db.execute(
            """
            INSERT INTO sales

            (
                user_id,
                bill_no,
                customer_name,
                total,
                sale_date
            )

            VALUES (?, ?, ?, ?, ?)
            """,

            (
                user_id,
                bill_no,
                customer_name,
                subtotal,
                sale_date
            )
        )

        sale_id = cursor.lastrowid

        # Insert sale item

        db.execute(
            """
            INSERT INTO sale_items

            (
                user_id,
                sale_id,
                product_id,
                quantity,
                price,
                subtotal
            )

            VALUES (?, ?, ?, ?, ?, ?)
            """,

            (
                user_id,
                sale_id,
                product_id,
                quantity,
                product["price"],
                subtotal
            )
        )

        # Reduce product stock

        db.execute(
            """
            UPDATE products

            SET stock = stock - ?

            WHERE id = ?
            AND user_id = ?
            """,

            (
                quantity,
                product_id,
                user_id
            )
        )

        db.commit()

        db.close()

        flash(
            f"Bill {bill_no} generated successfully!"
        )

        return redirect(
            url_for("sales")
        )

    db.close()

    return render_template(
        "billing.html",
        products=products_data
    )


# ---------------- SALES ----------------

@app.route("/sales")
def sales():

    if not login_required():

        return redirect(
            url_for("login")
        )

    user_id = session["user_id"]

    db = get_db()

    # Show only current user's sales

    sales_data = db.execute(
        """
        SELECT *

        FROM sales

        WHERE user_id = ?

        ORDER BY id DESC
        """,
        (user_id,)
    ).fetchall()

    db.close()

    return render_template(
        "sales.html",
        sales=sales_data
    )


# ---------------- SETTINGS ----------------

@app.route(
    "/settings",
    methods=["GET", "POST"]
)
def settings():

    if not login_required():

        return redirect(
            url_for("login")
        )

    user_id = session["user_id"]

    db = get_db()

    # Update settings

    if request.method == "POST":

        shop_name = request.form[
            "shop_name"
        ]

        owner_name = request.form[
            "owner_name"
        ]

        db.execute(
            """
            UPDATE settings

            SET
                shop_name = ?,
                owner_name = ?

            WHERE user_id = ?
            """,

            (
                shop_name,
                owner_name,
                user_id
            )
        )

        db.commit()

        flash(
            "Settings updated successfully!"
        )

    # Get current user's settings

    setting = db.execute(
        """
        SELECT *

        FROM settings

        WHERE user_id = ?
        """,
        (user_id,)
    ).fetchone()

    db.close()

    return render_template(
        "settings.html",
        setting=setting
    )


# ---------------- LOGOUT ----------------

@app.route("/logout")
def logout():

    # Remove current user's session

    session.clear()

    return render_template(
        "logout.html"
    )


# ---------------- RUN APPLICATION ----------------

if __name__ == "__main__":

    create_database()

    app.run(
        debug=True
    )