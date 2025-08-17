# app.py
"""
InvyPro — Single-file Streamlit Inventory Manager
- Multi-user (signup/login)
- Per-organization isolation (one org's data is only visible to its users)
- SQLite persistence (users, suppliers, products, transactions, audit_logs)
- Demo preview when logged out
- Proper widget keys, forms, and safe password hashing
- Minimal external deps: streamlit, pandas, altair, pytz
"""

import os
import sqlite3
import secrets
import hashlib
import hmac
import time
from contextlib import contextmanager
from datetime import datetime, timedelta
from typing import Optional, Tuple, Dict

import pandas as pd
import streamlit as st
import altair as alt
import pytz

# ---------------------------
# App config
# ---------------------------
st.set_page_config(page_title="InvyPro — Inventory Manager", page_icon="📦", layout="wide")

# ---------------------------
# Simple CSS polish
# ---------------------------
st.markdown(
    """
    <style>
    :root{--muted:#6b7280;--cardb:#eef2f6;--text:#0f172a;--ok:#035b6a;--low:#861b1b;}
    .report-card{border:1px solid var(--cardb);border-radius:10px;padding:12px;margin-bottom:10px;background:#fff;}
    .small-label{font-size:0.85rem;color:var(--muted);margin-bottom:0.25rem;}
    .big-num{font-size:1.4rem;font-weight:700;margin:0;color:var(--text);}
    .badge{display:inline-block;padding:4px 10px;border-radius:999px;background:#f1f5f9;font-size:0.78rem;margin-top:6px;}
    .low{background:#fff1f2;color:var(--low);}
    .ok{background:#ecfeff;color:var(--ok);}
    .muted{color:var(--muted);}
    .hero{padding:14px;border-radius:10px;background:linear-gradient(180deg,#f8fafc,#ffffff);margin-bottom:12px;}
    </style>
    """,
    unsafe_allow_html=True,
)

# ---------------------------
# Database utilities
# ---------------------------
DB_PATH = os.getenv("INVYPRO_DB", "invypro.db")
_conn = None


def get_conn():
    global _conn
    if _conn is None:
        _conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        _conn.execute("PRAGMA foreign_keys = ON;")
        _conn.row_factory = sqlite3.Row
    return _conn


@contextmanager
def db_session():
    conn = get_conn()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise


def init_db():
    with db_session() as conn:
        cur = conn.cursor()
        # Users: note organization IS NOT UNIQUE so multiple users can belong to same organization
        cur.execute(
            """
        CREATE TABLE IF NOT EXISTS users (
            user_id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            email TEXT,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            organization TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'admin',
            is_active INTEGER DEFAULT 1,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            last_login TEXT
        );
        """
        )
        cur.execute(
            """
        CREATE TABLE IF NOT EXISTS suppliers (
            supplier_id INTEGER PRIMARY KEY AUTOINCREMENT,
            organization TEXT NOT NULL,
            name TEXT NOT NULL,
            phone TEXT,
            email TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(organization, name)
        );
        """
        )
        cur.execute(
            """
        CREATE TABLE IF NOT EXISTS products (
            product_id INTEGER PRIMARY KEY AUTOINCREMENT,
            organization TEXT NOT NULL,
            sku TEXT NOT NULL,
            name TEXT NOT NULL,
            category TEXT,
            supplier_id INTEGER,
            cost_price REAL DEFAULT 0,
            sell_price REAL DEFAULT 0,
            qty INTEGER DEFAULT 0,
            reorder_level INTEGER DEFAULT 0,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(supplier_id) REFERENCES suppliers(supplier_id) ON DELETE SET NULL,
            UNIQUE(organization, sku)
        );
        """
        )
        cur.execute(
            """
        CREATE TABLE IF NOT EXISTS transactions (
            txn_id INTEGER PRIMARY KEY AUTOINCREMENT,
            organization TEXT NOT NULL,
            product_id INTEGER NOT NULL,
            type TEXT NOT NULL CHECK(type IN ('sale','restock','adjustment')),
            quantity INTEGER NOT NULL,
            amount REAL DEFAULT 0,
            note TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(product_id) REFERENCES products(product_id) ON DELETE CASCADE
        );
        """
        )
        cur.execute(
            """
        CREATE TABLE IF NOT EXISTS audit_logs (
            log_id INTEGER PRIMARY KEY AUTOINCREMENT,
            organization TEXT NOT NULL,
            user_id INTEGER,
            action TEXT NOT NULL,
            details TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
        """
        )


init_db()

# ---------------------------
# Helpers: time, hashing, DB wrappers
# ---------------------------
def now_iso():
    tz = pytz.timezone(st.session_state.get("timezone", "UTC")) if "timezone" in st.session_state else pytz.UTC
    return datetime.now(tz).isoformat(timespec="seconds")


def hash_password(password: str, salt: Optional[str] = None) -> Tuple[str, str]:
    if salt is None:
        salt = secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 100_000).hex()
    return h, salt


def verify_password(stored_hash: str, stored_salt: str, provided_password: str) -> bool:
    computed, _ = hash_password(provided_password, stored_salt)
    try:
        return hmac.compare_digest(computed, stored_hash)
    except Exception:
        return False


def run_query(query: str, params: Tuple = ()):
    with db_session() as conn:
        conn.execute(query, params)


def fetch_df(query: str, params: Tuple = ()) -> pd.DataFrame:
    with db_session() as conn:
        return pd.read_sql_query(query, conn, params=params)


def log_audit(action: str, details: str = ""):
    org = st.session_state.get("organization", "PUBLIC")
    uid = st.session_state.get("user_id")
    run_query(
        "INSERT INTO audit_logs (organization, user_id, action, details, created_at) VALUES (?,?,?,?,?);",
        (org, uid, action, details, now_iso()),
    )


# ---------------------------
# Session defaults & lockout
# ---------------------------
if "authenticated" not in st.session_state:
    st.session_state.authenticated = False
if "username" not in st.session_state:
    st.session_state.username = None
if "user_id" not in st.session_state:
    st.session_state.user_id = None
if "organization" not in st.session_state:
    st.session_state.organization = None
if "role" not in st.session_state:
    st.session_state.role = "staff"
if "timezone" not in st.session_state:
    st.session_state.timezone = "UTC"
if "currency" not in st.session_state:
    st.session_state.currency = "GH₵"
if "prevent_negative_stock" not in st.session_state:
    st.session_state.prevent_negative_stock = True
if "demo_mode" not in st.session_state:
    st.session_state.demo_mode = True

# simple in-memory login attempts
if "login_attempts" not in st.session_state:
    st.session_state.login_attempts: Dict[str, Tuple[int, float]] = {}

LOCKOUT_AFTER = 6
LOCKOUT_SECS = 300


def is_locked(user: str) -> Optional[int]:
    rec = st.session_state.login_attempts.get(user or "", (0, 0))
    count, until = rec
    now = time.time()
    if until and now < until:
        return int(until - now)
    return None


def bump_fail(user: str):
    count, until = st.session_state.login_attempts.get(user or "", (0, 0))
    count += 1
    if count >= LOCKOUT_AFTER:
        st.session_state.login_attempts[user or ""] = (0, time.time() + LOCKOUT_SECS)
    else:
        st.session_state.login_attempts[user or ""] = (count, 0)


def clear_fail(user: str):
    if user in st.session_state.login_attempts:
        del st.session_state.login_attempts[user]


# ---------------------------
# Auth functions: signup/login/logout
# ---------------------------
def signup(username: str, email: str, password: str, organization: str):
    username = (username or "").strip().lower()
    organization = (organization or "").strip()
    email = (email or "").strip().lower()
    if not username or not password or not organization:
        st.error("Username, password and organization are required.")
        return
    if len(username) > 60 or len(organization) > 80:
        st.error("Username or organization too long.")
        return
    phash, salt = hash_password(password)
    try:
        with db_session() as conn:
            conn.execute(
                "INSERT INTO users (username, email, password_hash, salt, organization, role, is_active, created_at) VALUES (?,?,?,?,?,'admin',1,?);",
                (username, email, phash, salt, organization, now_iso()),
            )
        st.success("Account created. Please log in.")
        log_audit("signup", f"user={username}, org={organization}")
    except sqlite3.IntegrityError as e:
        msg = str(e).lower()
        if "unique" in msg and "username" in msg:
            st.error("Username already exists.")
        else:
            st.error("Could not create account. Try different username/organization/email.")


def login(username: str, password: str):
    username = (username or "").strip().lower()
    if not username or not password:
        st.error("Fill both username and password.")
        return
    locked = is_locked(username)
    if locked:
        st.error(f"Too many attempts. Try again in {locked}s.")
        return
    with db_session() as conn:
        row = conn.execute("SELECT user_id, username, password_hash, salt, organization, role, is_active FROM users WHERE username=?;", (username,)).fetchone()
    if not row:
        st.error("Invalid credentials.")
        bump_fail(username)
        return
    if not row["is_active"]:
        st.error("Account inactive.")
        return
    if verify_password(row["password_hash"], row["salt"], password):
        # success
        st.session_state.authenticated = True
        st.session_state.user_id = row["user_id"]
        st.session_state.username = row["username"]
        st.session_state.organization = row["organization"]
        st.session_state.role = row["role"]
        st.session_state.demo_mode = False
        conn = get_conn()
        conn.execute("UPDATE users SET last_login=? WHERE user_id=?;", (now_iso(), row["user_id"]))
        clear_fail(username)
        log_audit("login", f"user={username}")
        st.experimental_rerun()
    else:
        st.error("Invalid credentials.")
        bump_fail(username)
        return


def logout():
    if st.session_state.authenticated:
        log_audit("logout", f"user={st.session_state.username}")
    # clear state but keep preferences
    tz = st.session_state.get("timezone", "UTC")
    cur = st.session_state.get("currency", "GH₵")
    pns = st.session_state.get("prevent_negative_stock", True)
    st.session_state.clear()
    st.session_state.authenticated = False
    st.session_state.username = None
    st.session_state.user_id = None
    st.session_state.organization = None
    st.session_state.role = "staff"
    st.session_state.timezone = tz
    st.session_state.currency = cur
    st.session_state.prevent_negative_stock = pns
    st.session_state.demo_mode = True
    st.experimental_rerun()


# ---------------------------
# Data helpers (org-scoped)
# ---------------------------
def current_org() -> Optional[str]:
    return st.session_state.organization if st.session_state.authenticated else None


def upsert_supplier(name: str, phone: Optional[str], email: Optional[str]) -> int:
    if not name or len(name) > 100:
        raise ValueError("Invalid supplier name")
    org = current_org()
    if not org:
        raise PermissionError("Login required")
    with db_session() as conn:
        cur = conn.cursor()
        row = cur.execute("SELECT supplier_id FROM suppliers WHERE organization=? AND name=?;", (org, name)).fetchone()
        if row:
            sid = row["supplier_id"]
            cur.execute("UPDATE suppliers SET phone=?, email=? WHERE supplier_id=?;", (phone, email, sid))
        else:
            cur.execute("INSERT INTO suppliers (organization, name, phone, email, created_at) VALUES (?,?,?,?,?);", (org, name, phone, email, now_iso()))
            sid = cur.lastrowid
        log_audit("upsert_supplier", f"name={name}, id={sid}")
        return sid


def upsert_product(sku: str, name: str, category: str, supplier_name: str, cost_price: float, sell_price: float, qty: int, reorder_level: int) -> int:
    org = current_org()
    if not org:
        raise PermissionError("Login required")
    if not sku or not name:
        raise ValueError("SKU and name required")
    if any(x < 0 for x in (cost_price, sell_price, qty, reorder_level)):
        raise ValueError("Negative values not allowed")
    supplier_id = None
    if supplier_name:
        supplier_id = upsert_supplier(supplier_name, None, None)
    with db_session() as conn:
        cur = conn.cursor()
        row = cur.execute("SELECT product_id FROM products WHERE organization=? AND sku=?;", (org, sku)).fetchone()
        if row:
            pid = row["product_id"]
            cur.execute("""UPDATE products SET name=?, category=?, supplier_id=?, cost_price=?, sell_price=?, qty=?, reorder_level=? WHERE product_id=? AND organization=?;""",
                        (name, category, supplier_id, cost_price, sell_price, qty, reorder_level, pid, org))
        else:
            cur.execute("""INSERT INTO products (organization, sku, name, category, supplier_id, cost_price, sell_price, qty, reorder_level, created_at) VALUES (?,?,?,?,?,?,?,?,?,?);""",
                        (org, sku, name, category, supplier_id, cost_price, sell_price, qty, reorder_level, now_iso()))
            pid = cur.lastrowid
        log_audit("upsert_product", f"sku={sku}, id={pid}")
        return pid


def products_df(page: int = 1, page_size: int = 50, for_search: bool = False) -> pd.DataFrame:
    if st.session_state.demo_mode:
        return pd.DataFrame()
    org = current_org()
    if not org:
        return pd.DataFrame()
    offset = (page - 1) * page_size
    if for_search:
        q = """SELECT p.product_id, p.sku, p.name, p.category, (SELECT name FROM suppliers s WHERE s.supplier_id=p.supplier_id) as supplier, p.cost_price, p.sell_price, p.qty, p.reorder_level, p.created_at
               FROM products p WHERE p.organization=? ORDER BY p.created_at DESC;"""
        return fetch_df(q, (org,))
    else:
        q = """SELECT p.product_id, p.sku, p.name, p.category, (SELECT name FROM suppliers s WHERE s.supplier_id=p.supplier_id) as supplier, p.cost_price, p.sell_price, p.qty, p.reorder_level, p.created_at
               FROM products p WHERE p.organization=? ORDER BY p.created_at DESC LIMIT ? OFFSET ?;"""
        return fetch_df(q, (org, page_size, offset))


def transactions_df(days: Optional[int] = None, product_id: Optional[int] = None) -> pd.DataFrame:
    if st.session_state.demo_mode:
        return pd.DataFrame()
    org = current_org()
    if not org:
        return pd.DataFrame()
    q = """SELECT t.txn_id, t.product_id, p.sku, p.name, t.type, t.quantity, t.amount, t.note, t.created_at
           FROM transactions t JOIN products p ON p.product_id=t.product_id WHERE t.organization=?"""
    params = [org]
    conds = []
    if product_id:
        conds.append("t.product_id=?"); params.append(product_id)
    if days:
        since = (datetime.utcnow() - timedelta(days=days)).isoformat(timespec="seconds")
        conds.append("t.created_at>=?"); params.append(since)
    if conds:
        q += " AND " + " AND ".join(conds)
    q += " ORDER BY t.created_at DESC;"
    return fetch_df(q, tuple(params))


def calc_kpis(currency: str = "GH₵") -> dict:
    if st.session_state.demo_mode:
        return dict(total_skus=0, stock_value=f"{currency} 0.00", low_stock=0, sales_rev_30d=f"{currency} 0.00")
    org = current_org()
    if not org:
        return dict(total_skus=0, stock_value=f"{currency} 0.00", low_stock=0, sales_rev_30d=f"{currency} 0.00")
    prods = fetch_df("SELECT qty,cost_price,reorder_level FROM products WHERE organization=?;", (org,))
    tx30 = transactions_df(30)
    total_skus = 0 if prods.empty else prods.shape[0]
    stock_value = 0.0 if prods.empty else float((prods["qty"] * prods["cost_price"]).sum())
    low_stock = 0 if prods.empty else int((prods["qty"] <= prods["reorder_level"]).sum())
    sales_rev_30d = 0.0 if tx30.empty else float(tx30[tx30["type"] == "sale"]["amount"].sum())
    return dict(total_skus=total_skus, stock_value=f"{currency} {stock_value:,.2f}", low_stock=low_stock, sales_rev_30d=f"{currency} {sales_rev_30d:,.2f}")


def to_csv_download(df: pd.DataFrame, prefix: str) -> Tuple[bytes, str]:
    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    csv = df.to_csv(index=False).encode("utf-8")
    return csv, f"{prefix}_{ts}.csv"


def add_transaction(product_id: int, ttype: str, quantity: int, amount: float = 0.0, note: str = ""):
    org = current_org()
    if not org:
        st.error("Login required.")
        return
    prod = fetch_df("SELECT qty FROM products WHERE product_id=? AND organization=?;", (product_id, org))
    if prod.empty:
        st.error("Product not found.")
        return
    current_qty = int(prod["qty"].iloc[0])
    prevent_negative = st.session_state.get("prevent_negative_stock", True)
    if prevent_negative:
        if ttype == "sale" and quantity > current_qty:
            st.error(f"Cannot sell {quantity}. Only {current_qty} in stock.")
            return
        if ttype == "adjustment" and (current_qty + quantity) < 0:
            st.error("Adjustment would result in negative stock.")
            return
    if ttype == "sale":
        run_query("UPDATE products SET qty=qty-? WHERE product_id=? AND organization=?;", (quantity, product_id, org))
    else:
        run_query("UPDATE products SET qty=qty+? WHERE product_id=? AND organization=?;", (quantity, product_id, org))
    run_query("INSERT INTO transactions (organization, product_id, type, quantity, amount, note, created_at) VALUES (?,?,?,?,?,?,?);",
              (org, product_id, ttype, quantity, amount, note, now_iso()))
    log_audit("add_transaction", f"type={ttype}, pid={product_id}, qty={quantity}, amt={amount}")


# ---------------------------
# Demo preview data (when logged out)
# ---------------------------
def demo_products_df():
    return pd.DataFrame([
        dict(product_id=1, sku="SKU-001", name="Bottled Water 500ml", category="Drinks", supplier="AquaPlus Ltd", cost_price=1.5, sell_price=2.5, qty=120, reorder_level=30, created_at=now_iso()),
        dict(product_id=2, sku="SKU-002", name="Bottled Water 1.5L", category="Drinks", supplier="AquaPlus Ltd", cost_price=3.0, sell_price=5.0, qty=80, reorder_level=20, created_at=now_iso()),
        dict(product_id=3, sku="SKU-101", name="Rice 5kg", category="Groceries", supplier="FreshFoods Co", cost_price=60.0, sell_price=85.0, qty=40, reorder_level=10, created_at=now_iso()),
    ])


def demo_transactions_df():
    now = datetime.utcnow()
    rows = [
        dict(txn_id=1, product_id=1, sku="SKU-001", name="Bottled Water 500ml", type="sale", quantity=10, amount=25.0, note="Demo", created_at=(now - timedelta(days=7)).isoformat(timespec="seconds")),
        dict(txn_id=2, product_id=1, sku="SKU-001", name="Bottled Water 500ml", type="sale", quantity=12, amount=30.0, note="Demo", created_at=(now - timedelta(days=2)).isoformat(timespec="seconds")),
        dict(txn_id=3, product_id=3, sku="SKU-101", name="Rice 5kg", type="restock", quantity=10, amount=600.0, note="Demo", created_at=(now - timedelta(days=14)).isoformat(timespec="seconds")),
    ]
    return pd.DataFrame(rows)


# ---------------------------
# UI: sidebar auth (forms with unique keys!)
# ---------------------------
st.sidebar.title("📦 InvyPro")

if not st.session_state.authenticated:
    with st.sidebar.expander("🔐 Login", expanded=True):
        with st.form("login_form"):
            li_user = st.text_input("Username", key="login_username")
            li_pass = st.text_input("Password", type="password", key="login_password")
            login_sub = st.form_submit_button("Log in", use_container_width=True)
            if login_sub:
                login(li_user, li_pass)

    with st.sidebar.expander("✨ Create account"):
        with st.form("signup_form"):
            su_user = st.text_input("Choose username", key="signup_username")
            su_email = st.text_input("Email (optional)", key="signup_email")
            su_org = st.text_input("Organization name", key="signup_org")
            su_pass = st.text_input("Password", type="password", key="signup_password")
            signup_sub = st.form_submit_button("Create account", use_container_width=True)
            if signup_sub:
                signup(su_user, su_email, su_pass, su_org)
else:
    st.sidebar.success(f"@{st.session_state.username} — {st.session_state.organization}")
    if st.sidebar.button("Logout", key="logout_btn", use_container_width=True):
        logout()

# navigation
PAGE_OPTIONS = ["Dashboard", "Products", "Sales & Restock", "Suppliers", "Transactions", "Stock History", "Bulk Upload / Export", "Settings"]
page = st.sidebar.radio("Navigate", PAGE_OPTIONS, index=0)

# ---------------------------
# Small helper
# ---------------------------
def require_login_message():
    st.warning("You're in demo/public preview. Please log in to manage real data.")

# ---------------------------
# PAGES
# ---------------------------
if page == "Dashboard":
    if st.session_state.demo_mode:
        st.markdown('<div class="hero"><h1>InvyPro — Inventory Manager</h1><p class="muted">Sign up or log in to manage your inventory. Below is a demo preview.</p></div>', unsafe_allow_html=True)
        prods = demo_products_df()
        txns = demo_transactions_df()
    else:
        prods = fetch_df("SELECT sku,name,category,cost_price,sell_price,qty,reorder_level,created_at FROM products WHERE organization=? ORDER BY created_at DESC;", (current_org(),))
        txns = transactions_df(90)

    # KPIs
    if prods.empty:
        total_skus = 0
        stock_value = f"{st.session_state.currency} 0.00"
        low_stock = 0
    else:
        total_skus = len(prods)
        stock_value_val = float((prods["qty"] * prods["cost_price"]).sum()) if "qty" in prods.columns else 0.0
        stock_value = f"{st.session_state.currency} {stock_value_val:,.2f}"
        low_stock = int((prods["qty"] <= prods["reorder_level"]).sum()) if "reorder_level" in prods.columns else 0
    sales_rev = float(txns[txns["type"] == "sale"]["amount"].sum()) if not txns.empty else 0.0

    c1, c2, c3, c4 = st.columns(4)
    with c1:
        st.markdown(f'<div class="report-card"><div class="small-label">Total SKUs</div><div class="big-num">{total_skus}</div></div>', unsafe_allow_html=True)
    with c2:
        st.markdown(f'<div class="report-card"><div class="small-label">Stock Value</div><div class="big-num">{stock_value}</div></div>', unsafe_allow_html=True)
    with c3:
        cls = "badge low" if low_stock > 0 else "badge ok"
        txt = "Action needed" if low_stock > 0 else "All good"
        st.markdown(f'<div class="report-card"><div class="small-label">Low-Stock Items</div><div class="big-num">{low_stock}</div><div class="{cls}">{txt}</div></div>', unsafe_allow_html=True)
    with c4:
        st.markdown(f'<div class="report-card"><div class="small-label">Sales (Last 90d)</div><div class="big-num">{st.session_state.currency} {sales_rev:,.2f}</div></div>', unsafe_allow_html=True)

    st.divider()
    if txns.empty:
        st.info("No sales yet.")
    else:
        sales = txns[txns["type"] == "sale"].copy()
        sales["date"] = pd.to_datetime(sales["created_at"]).dt.date
        trend = sales.groupby("date", as_index=False)["amount"].sum()
        chart = alt.Chart(trend).mark_line(point=True).encode(x="date:T", y=alt.Y("amount:Q", title=f"Revenue ({st.session_state.currency})"), tooltip=["date:T", alt.Tooltip("amount:Q", format=",.2f")]).properties(height=300, title="Sales Revenue")
        st.altair_chart(chart, use_container_width=True)

    st.subheader("Products")
    st.dataframe(prods if not prods.empty else demo_products_df(), use_container_width=True, hide_index=True)


# =======================
# 📦 PRODUCTS PAGE
# =======================
elif page == "Products":
    st.header("🧾 Products")

    # --- Database setup ---
    def init_db():
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute("""
            CREATE TABLE IF NOT EXISTS products (
                sku TEXT PRIMARY KEY,
                name TEXT,
                category TEXT,
                supplier TEXT,
                cost_price REAL,
                sell_price REAL,
                qty INTEGER,
                reorder_level INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.commit()
        conn.close()

    def add_product(sku, name, category, supplier, cost_price, sell_price, qty, reorder_level):
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute("""
            INSERT OR REPLACE INTO products (sku, name, category, supplier, cost_price, sell_price, qty, reorder_level)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (sku, name, category, supplier, cost_price, sell_price, qty, reorder_level))
        conn.commit()
        conn.close()

    def list_products():
        conn = sqlite3.connect(DB_FILE)
        df = pd.read_sql_query("SELECT * FROM products ORDER BY created_at DESC", conn)
        conn.close()
        return df

    def delete_product(sku):
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute("DELETE FROM products WHERE sku=?", (sku,))
        conn.commit()
        conn.close()

    # Ensure DB is ready
    init_db()

    # --- Add / Edit Product ---
    with st.expander("➕ Add / Edit Product"):
        sku = st.text_input("SKU *")
        name = st.text_input("Name *")
        colA, colB, colC = st.columns(3)
        with colA: category = st.text_input("Category")
        with colB: supplier_name = st.text_input("Supplier")
        with colC: reorder_level = st.number_input("Reorder Level", min_value=0, max_value=10**9, value=0, step=1)

        col1, col2, col3 = st.columns(3)
        with col1: cost_price = st.number_input("Cost Price", min_value=0.0, max_value=float(1e12), value=0.0, step=0.01, format="%.2f")
        with col2: sell_price = st.number_input("Sell Price", min_value=0.0, max_value=float(1e12), value=0.0, step=0.01, format="%.2f")
        with col3: qty = st.number_input("Initial Quantity", min_value=0, max_value=10**9, value=0, step=1)

        if st.button("💾 Save Product", type="primary"):
            if not sku or not name:
                st.error("SKU and Name are required.")
            else:
                add_product(
                    sku.strip(), name.strip(), category.strip(), supplier_name.strip(),
                    float(cost_price), float(sell_price), int(qty), int(reorder_level)
                )
                st.success(f"✅ Product '{name}' saved.")
                st.experimental_rerun()

    # --- Product List ---
    st.subheader("📄 Product List")
    q = st.text_input("Search (SKU / Name / Category)")
    page_num = st.number_input("Page", min_value=1, value=1, step=1)
    page_size = 20

    all_products = list_products()

    # Filter
    filtered = all_products
    if q:
        ql = q.strip().lower()
        filtered = all_products[
            all_products.apply(lambda r: ql in str(r["sku"]).lower()
                                         or ql in str(r["name"]).lower()
                                         or ql in str(r.get("category","")).lower(), axis=1)
        ]

    total = len(filtered)
    total_pages = max(1, -(-total // page_size))
    page_num = min(page_num, total_pages)
    start = (page_num - 1) * page_size
    df_page = filtered.iloc[start:start+page_size]

    st.caption(f"Showing {len(df_page)} items — page {page_num}/{total_pages} — {total} total matching")
    st.dataframe(df_page, use_container_width=True, hide_index=True)

    # --- Delete Product ---
    if not df_page.empty:
        st.markdown("---")
        del_sku = st.selectbox("🗑️ Delete product by SKU", options=["-- select --"] + df_page["sku"].astype(str).tolist())
        if st.button("Delete", type="secondary") and del_sku != "-- select --":
            delete_product(del_sku)
            st.warning(f"❌ Deleted product SKU {del_sku}")
            st.experimental_rerun()
            

## Sale & Restock Page
elif page == "Sales & Restock":
    st.header("🧾 Sales & Restock")
    if st.session_state.demo_mode:
        require_login_message()
    # list products
    if st.session_state.demo_mode:
        prods = demo_products_df()
    else:
        prods = fetch_df("SELECT product_id, sku, name, sell_price, cost_price, qty FROM products WHERE organization=? ORDER BY name;", (current_org(),))
    if prods.empty:
        st.info("No products available.")
    else:
        select_label = st.selectbox("Select product", options=[f"{r['sku']} — {r['name']}" for _, r in prods.iterrows()], key="txn_product_select")
        selected_idx = [f"{r['sku']} — {r['name']}" for _, r in prods.iterrows()].index(select_label)
        row = prods.iloc[selected_idx]
        pid = int(row["product_id"])
        sell_price = float(row["sell_price"]) if "sell_price" in row else 0.0
        cost_price = float(row["cost_price"]) if "cost_price" in row else 0.0

        col1, col2 = st.columns(2)
        with col1:
            ttype = st.selectbox("Transaction Type", ["sale", "restock", "adjustment"], key="txn_type")
        with col2:
            if ttype == "adjustment":
                qty = st.number_input("Quantity (negative to subtract)", value=0, step=1, key="txn_qty_adj")
            else:
                qty = st.number_input("Quantity", min_value=1, value=1, step=1, key="txn_qty_pos")
        note = st.text_input("Note (optional)", key="txn_note")

        if ttype == "sale":
            default_amt = sell_price * qty
        elif ttype == "restock":
            default_amt = cost_price * qty
        else:
            default_amt = 0.0
        amt = st.number_input(f"Amount ({st.session_state.currency})", value=float(default_amt), step=0.01, format="%.2f", key="txn_amount")

        disabled = st.session_state.demo_mode or not st.session_state.authenticated
        if st.button("Record Transaction", key="txn_record_btn", disabled=disabled):
            if disabled:
                require_login_message()
            else:
                if ttype in ("sale", "restock") and qty <= 0:
                    st.error("Quantity must be positive for sale/restock.")
                else:
                    add_transaction(pid, ttype, int(qty), float(amt), note)
                    st.success("Transaction recorded.")
                    log_audit("ui_record_txn", f"pid={pid}, type={ttype}, qty={qty}")

    st.divider()
    st.subheader("Recent Transactions (last 30 days)")
    if st.session_state.demo_mode:
        st.dataframe(demo_transactions_df(), use_container_width=True, hide_index=True)
    else:
        st.dataframe(transactions_df(30), use_container_width=True, hide_index=True)

elif page == "Suppliers":
    st.header("🤝 Suppliers")
    if st.session_state.demo_mode:
        require_login_message()
    name = st.text_input("Supplier Name", key="sup_name")
    phone = st.text_input("Phone", key="sup_phone")
    email = st.text_input("Email", key="sup_email")
    if st.button("Save Supplier", key="save_supplier_btn", disabled=st.session_state.demo_mode or not st.session_state.authenticated):
        if st.session_state.demo_mode:
            require_login_message()
        else:
            try:
                sid = upsert_supplier(name.strip(), phone.strip(), email.strip())
                st.success(f"Saved supplier (id={sid})")
            except Exception as e:
                st.error(str(e))
    st.subheader("Supplier List")
    if st.session_state.demo_mode:
        st.info("Login to manage suppliers.")
    else:
        sups = fetch_df("SELECT supplier_id, name, phone, email, created_at FROM suppliers WHERE organization=? ORDER BY name;", (current_org(),))
        st.dataframe(sups, use_container_width=True, hide_index=True)

elif page == "Transactions":
    st.header("📜 Transactions")
    if st.session_state.demo_mode:
        require_login_message()
        st.dataframe(demo_transactions_df(), use_container_width=True, hide_index=True)
    else:
        tx = transactions_df()
        if tx.empty:
            st.info("No transactions.")
        else:
            c1, c2, c3 = st.columns(3)
            with c1:
                f_type = st.selectbox("Type filter", options=["All", "sale", "restock", "adjustment"], key="tx_filter_type")
            with c2:
                start_date = st.date_input("Start date", value=(datetime.utcnow().date() - timedelta(days=30)), key="tx_start")
            with c3:
                end_date = st.date_input("End date", value=datetime.utcnow().date(), key="tx_end")
            fdf = tx.copy()
            fdf["dt"] = pd.to_datetime(fdf["created_at"])
            tz = pytz.timezone(st.session_state.timezone)
            start_ts = pd.Timestamp(start_date).tz_localize(tz)
            end_ts = pd.Timestamp(end_date).tz_localize(tz) + pd.Timedelta(days=1)
            fdf = fdf[(fdf["dt"] >= start_ts) & (fdf["dt"] < end_ts)]
            if f_type != "All":
                fdf = fdf[fdf["type"] == f_type]
            st.dataframe(fdf.drop(columns=["dt"]), use_container_width=True, hide_index=True)
            csv, fname = to_csv_download(fdf.drop(columns=["dt"]), f"transactions_{start_date}_to_{end_date}")
            st.download_button("Download CSV", data=csv, file_name=fname, mime="text/csv", key="tx_download")

elif page == "Stock History":
    st.header("📈 Stock History")
    if st.session_state.demo_mode:
        require_login_message()
    else:
        prods = fetch_df("SELECT product_id, sku, name FROM products WHERE organization=? ORDER BY name;", (current_org(),))
        if prods.empty:
            st.info("No products.")
        else:
            sku = st.selectbox("Select product", options=["-- select --"] + prods["sku"].tolist(), key="stock_hist_select")
            if sku != "-- select --":
                pid = int(prods[prods["sku"] == sku]["product_id"].iloc[0])
                tx = transactions_df(product_id=pid)
                if tx.empty:
                    st.info("No transactions for this product.")
                else:
                    tx["date"] = pd.to_datetime(tx["created_at"]).dt.date
                    tx["stock_change"] = tx.apply(lambda r: -r["quantity"] if r["type"] == "sale" else r["quantity"], axis=1)
                    chart = alt.Chart(tx).mark_line(point=True).encode(x="date:T", y="stock_change:Q", color="type:N", tooltip=["date:T", "type:N", "quantity:Q"]).properties(height=300)
                    st.altair_chart(chart, use_container_width=True)
                    st.dataframe(tx[["sku", "name", "type", "quantity", "amount", "note", "created_at"]], use_container_width=True, hide_index=True)

elif page == "Bulk Upload / Export":
    st.header("📥 Bulk Upload / Export")
    if st.session_state.demo_mode:
        require_login_message()
    else:
        st.subheader("Upload Products CSV")
        st.caption("Columns: sku, name, category, supplier, cost_price, sell_price, qty, reorder_level")
        up = st.file_uploader("Choose product CSV", type=["csv"], key="bulk_products")
        if up and st.session_state.authenticated:
            df = pd.read_csv(up)
            required = {"sku", "name"}
            if not required.issubset(set(df.columns)):
                st.error("CSV must include at least: sku, name.")
            else:
                count, errors = 0, []
                for i, r in df.fillna("").iterrows():
                    try:
                        upsert_product(str(r.get("sku", "")).strip(), str(r.get("name", "")).strip(), str(r.get("category", "")).strip(), str(r.get("supplier", "")).strip(), float(r.get("cost_price", 0) or 0), float(r.get("sell_price", 0) or 0), int(r.get("qty", 0) or 0), int(r.get("reorder_level", 0) or 0))
                        count += 1
                    except Exception as e:
                        errors.append(f"Row {i+2}: {str(e)}")
                st.success(f"Upserted {count} products.")
                if errors:
                    err_csv = pd.DataFrame(errors, columns=["error"]).to_csv(index=False).encode("utf-8")
                    st.download_button("Download Error Report", data=err_csv, file_name="product_upload_errors.csv", mime="text/csv", key="bulk_errs")
                log_audit("bulk_products_upload", f"count={count}")

        st.divider()
        st.subheader("Upload Transactions CSV")
        st.caption("Columns: sku, type (sale/restock/adjustment), quantity, amount(optional), note(optional)")
        up2 = st.file_uploader("Choose transactions CSV", type=["csv"], key="bulk_tx")
        if up2 and st.session_state.authenticated:
            df2 = pd.read_csv(up2)
            required2 = {"sku", "type", "quantity"}
            if not required2.issubset(set(df2.columns)):
                st.error("CSV must include: sku, type, quantity.")
            else:
                products = fetch_df("SELECT sku, product_id FROM products WHERE organization=?;", (current_org(),))
                sku_to_pid = dict(zip(products["sku"], products["product_id"]))
                ok, fail, errors = 0, 0, []
                for i, r in df2.fillna("").iterrows():
                    sku = str(r.get("sku", "")).strip()
                    pid = sku_to_pid.get(sku)
                    ttype = str(r.get("type", "")).strip().lower()
                    qty = r.get("quantity", "")
                    amt = float(r.get("amount", 0) or 0)
                    note = str(r.get("note", ""))
                    if not pid:
                        errors.append(f"Row {i+2}: Invalid SKU '{sku}'"); fail += 1; continue
                    if ttype not in {"sale", "restock", "adjustment"}:
                        errors.append(f"Row {i+2}: Invalid type '{ttype}'"); fail += 1; continue
                    try:
                        qty_i = int(qty)
                        if ttype in ("sale", "restock") and qty_i < 1:
                            errors.append(f"Row {i+2}: Quantity must be positive"); fail += 1; continue
                        add_transaction(pid, ttype, qty_i, amt, note)
                        ok += 1
                    except Exception as e:
                        errors.append(f"Row {i+2}: {str(e)}"); fail += 1
                st.success(f"Processed {ok} transactions. Skipped {fail}.")
                if errors:
                    err_csv = pd.DataFrame(errors, columns=["error"]).to_csv(index=False).encode("utf-8")
                    st.download_button("Download Transaction Errors", data=err_csv, file_name="transaction_upload_errors.csv", mime="text/csv", key="bulk_tx_errs")
                log_audit("bulk_transactions_upload", f"ok={ok}, fail={fail}")

        st.divider()
        st.subheader("Export Data")
        if st.button("Export Products CSV", key="exp_prods"):
            prods_df = fetch_df("SELECT sku,name,category,(SELECT name FROM suppliers s WHERE s.supplier_id=p.supplier_id) supplier,cost_price,sell_price,qty,reorder_level,created_at FROM products p WHERE organization=? ORDER BY created_at DESC;", (current_org(),))
            csv, name = to_csv_download(prods_df, "products_export")
            st.download_button("Download Products CSV", data=csv, file_name=name, mime="text/csv", key="download_prods")
        if st.button("Export Transactions CSV", key="exp_tx"):
            tx_df = transactions_df()
            csv2, name2 = to_csv_download(tx_df, "transactions_export")
            st.download_button("Download Transactions CSV", data=csv2, file_name=name2, mime="text/csv", key="download_tx")

elif page == "Settings":
    st.header("⚙️ Settings & Info")
    st.markdown("**InvyPro** — Local SQLite single-file app. Per-organization isolation.")
    tz_options = ["UTC", "Africa/Accra", "Europe/London", "America/New_York"]
    st.session_state.timezone = st.selectbox("Time Zone", tz_options, index=tz_options.index(st.session_state.timezone) if st.session_state.timezone in tz_options else 0, key="settings_tz")
    currency_options = ["GH₵", "USD $", "EUR €", "GBP £"]
    st.session_state.currency = st.selectbox("Currency", currency_options, index=currency_options.index(st.session_state.currency) if st.session_state.currency in currency_options else 0, key="settings_currency")
    st.session_state.prevent_negative_stock = st.checkbox("Prevent negative stock (sales & negative adjustments)", value=st.session_state.prevent_negative_stock, key="settings_prevent")

    st.divider()
    if st.session_state.authenticated:
        st.markdown("**Danger zone — organization only**")
        if st.button("Reset my organization data (delete products, transactions, suppliers)", key="reset_org"):
            org = current_org()
            if org:
                run_query("DELETE FROM transactions WHERE organization=?;", (org,))
                run_query("DELETE FROM products WHERE organization=?;", (org,))
                run_query("DELETE FROM suppliers WHERE organization=?;", (org,))
                run_query("DELETE FROM audit_logs WHERE organization=?;", (org,))
                log_audit("reset_org", "Org data cleared")
                st.success("Organization data cleared.")
    else:
        st.info("Log in to see organisation settings.")
