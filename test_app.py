# app.py
"""
InvyPro — Secure Multi-Tenant Inventory Manager (Single-file Streamlit app)

Key additions vs. your base:
- Real users table (username/email/password_salt_hash/role/org)
- PBKDF2-HMAC(SHA256) hashing + secrets.compare_digest
- Per-organization data isolation (every table + every query)
- Login & Signup with soft lockout on repeated failures
- Public "Demo Mode" (read-only, sample data, no writes)
- Same clean UI, upgraded CSS, one-file deploy
"""

import os
import io
import time
import hmac
import hashlib
import secrets
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta
from typing import Optional, Tuple, Dict

import pandas as pd
import streamlit as st
import altair as alt
import pytz

# -------------------------------
# App meta
# -------------------------------
st.set_page_config(
    page_title="InvyPro — Inventory Manager",
    page_icon="📦",
    layout="wide",
    initial_sidebar_state="expanded",
)

# -------------------------------
# CSS — crisp & delightful
# -------------------------------
st.markdown(
    """
    <style>
    :root {
      --card-bg:#ffffff; --card-b:#eef2f6; --text:#0f172a; --muted:#6b7280;
      --ok:#035b6a; --okbg:#ecfeff; --low:#861b1b; --lowbg:#fff1f2;
      --warn:#7a3419; --warnbg:#fff7ed; --success:#166534; --successbg:#f0fdf4;
    }
    .report-card {border:1px solid var(--card-b);border-radius:12px;padding:14px;margin-bottom:10px;background:var(--card-bg);}
    .small-label {font-size:0.85rem;color:var(--muted);margin-bottom:0.25rem;}
    .big-num {font-size:1.45rem;font-weight:800;margin:0;color:var(--text);}
    .badge {display:inline-block;padding:5px 10px;border-radius:999px;font-size:0.78rem;margin-top:6px;}
    .low {background:var(--lowbg);color:var(--low);}
    .ok  {background:var(--okbg);color:var(--ok);}
    .muted {color:var(--muted);font-size:0.9rem;}
    .block-space {margin-top:0.6rem;margin-bottom:0.6rem;}
    .danger {background:var(--warnbg);color:var(--warn);padding:6px;border-radius:6px;}
    .success {background:var(--successbg);color:var(--success);padding:6px;border-radius:6px;}
    .hero {padding:18px 18px;border-radius:14px;background:linear-gradient(180deg,#f8fafc, #ffffff)}
    .hero h1 {margin:0;font-size:1.75rem}
    </style>
    """,
    unsafe_allow_html=True,
)

# -------------------------------
# Database (SQLite) with org isolation
# -------------------------------
DB_PATH = os.getenv("INVYPRO_DB", "inventory_secure.db")
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
        c = conn.cursor()
        # Users
        c.execute("""
            CREATE TABLE IF NOT EXISTS users (
                user_id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                email TEXT UNIQUE,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                organization TEXT NOT NULL UNIQUE,
                role TEXT NOT NULL CHECK(role IN ('admin','manager','staff')) DEFAULT 'admin',
                is_active INTEGER DEFAULT 1,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                last_login TEXT
            );
        """)
        # Suppliers (org-scoped)
        c.execute("""
            CREATE TABLE IF NOT EXISTS suppliers (
                supplier_id INTEGER PRIMARY KEY AUTOINCREMENT,
                organization TEXT NOT NULL,
                name TEXT NOT NULL,
                phone TEXT,
                email TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(organization, name)
            );
        """)
        # Products (org-scoped)
        c.execute("""
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
        """)
        # Transactions (org-scoped)
        c.execute("""
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
        """)
        # Audit logs (org-scoped)
        c.execute("""
            CREATE TABLE IF NOT EXISTS audit_logs (
                log_id INTEGER PRIMARY KEY AUTOINCREMENT,
                organization TEXT NOT NULL,
                user_id INTEGER,
                action TEXT NOT NULL,
                details TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            );
        """)

init_db()

# -------------------------------
# Security helpers
# -------------------------------
def hash_password(password: str, salt: Optional[str] = None) -> Tuple[str, str]:
    if salt is None:
        salt = secrets.token_hex(16)
    pw_hash = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        100_000
    ).hex()
    return pw_hash, salt

def verify_password(stored_hash: str, stored_salt: str, provided_password: str) -> bool:
    computed, _ = hash_password(provided_password, stored_salt)
    try:
        return hmac.compare_digest(computed, stored_hash)
    except Exception:
        return False

def get_now_iso() -> str:
    tz_name = st.session_state.get("timezone", "UTC")
    try:
        tz = pytz.timezone(tz_name)
    except Exception:
        tz = pytz.UTC
    return datetime.now(tz).isoformat(timespec="seconds")

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
        (org, uid, action, details, get_now_iso()),
    )

# -------------------------------
# Session defaults + soft lockout
# -------------------------------
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
    st.session_state.demo_mode = True  # public preview until login

# in-memory login attempts: {username: (count, lockout_until_ts)}
if "login_attempts" not in st.session_state:
    st.session_state.login_attempts: Dict[str, Tuple[int, float]] = {}

LOCKOUT_AFTER = 5     # attempts
LOCKOUT_SECS  = 300   # 5 minutes

def is_locked(user: str) -> Optional[int]:
    rec = st.session_state.login_attempts.get(user or "", (0, 0))
    count, until_ts = rec
    now = time.time()
    if until_ts and now < until_ts:
        return int(until_ts - now)
    return None

def bump_login_fail(user: str):
    count, until_ts = st.session_state.login_attempts.get(user or "", (0, 0))
    count += 1
    if count >= LOCKOUT_AFTER:
        st.session_state.login_attempts[user or ""] = (0, time.time() + LOCKOUT_SECS)
    else:
        st.session_state.login_attempts[user or ""] = (count, 0)

def clear_login_fail(user: str):
    if user in st.session_state.login_attempts:
        del st.session_state.login_attempts[user]

# -------------------------------
# Auth: signup & login
# -------------------------------
def signup(username: str, email: str, password: str, organization: str):
    username = username.strip().lower()
    email = (email or "").strip().lower()
    organization = organization.strip()
    if not username or not password or not organization:
        st.error("Username, password, and organization are required.")
        return
    if len(username) > 60 or len(organization) > 80:
        st.error("Username/Organization too long.")
        return
    pw_hash, salt = hash_password(password)
    try:
        with db_session() as conn:
            conn.execute(
                """INSERT INTO users (username, email, password_hash, salt, organization, role, is_active, created_at)
                   VALUES (?,?,?,?,?,'admin',1,?);""",
                (username, email, pw_hash, salt, organization, get_now_iso()),
            )
        st.success("Account created! You can now log in.")
        log_audit("signup", f"user={username}, org={organization}")
    except sqlite3.IntegrityError as e:
        if "users.username" in str(e).lower():
            st.error("Username already exists.")
        elif "users.organization" in str(e).lower():
            st.error("Organization already taken. Choose a different name.")
        elif "users.email" in str(e).lower():
            st.error("Email already registered.")
        else:
            st.error("Could not create user.")

def login(username: str, password: str) -> bool:
    username = (username or "").strip().lower()
    if not username or not password:
        st.error("Enter username and password.")
        return False

    remain = is_locked(username)
    if remain:
        st.error(f"Too many attempts. Try again in {remain}s.")
        return False

    with db_session() as conn:
        row = conn.execute(
            "SELECT user_id, username, password_hash, salt, organization, role, is_active FROM users WHERE username = ?;",
            (username,),
        ).fetchone()
    if not row:
        st.error("Invalid credentials.")
        bump_login_fail(username)
        return False
    if not row["is_active"]:
        st.error("Account inactive.")
        return False

    if verify_password(row["password_hash"], row["salt"], password):
        # success
        st.session_state.update(
            authenticated=True,
            user_id=row["user_id"],
            username=row["username"],
            organization=row["organization"],
            role=row["role"],
            demo_mode=False,
        )
        with db_session() as conn:
            conn.execute("UPDATE users SET last_login=? WHERE user_id=?;", (get_now_iso(), row["user_id"]))
        clear_login_fail(username)
        log_audit("login", f"user={row['username']}")
        st.experimental_rerun()
        return True
    else:
        st.error("Invalid credentials.")
        bump_login_fail(username)
        return False

def logout():
    if st.session_state.get("authenticated"):
        log_audit("logout", f"user={st.session_state.get('username')}")
    st.session_state.clear()
    # restore defaults
    st.session_state.update(
        authenticated=False, username=None, user_id=None, organization=None, role="staff",
        timezone="UTC", currency="GH₵", prevent_negative_stock=True, demo_mode=True
    )
    st.experimental_rerun()

# -------------------------------
# Validation helpers
# -------------------------------
def validate_text_input(s: str, max_len: int, field: str) -> bool:
    if s is None: s = ""
    if not s.strip():
        st.error(f"{field} is required.")
        return False
    if len(s) > max_len:
        st.error(f"{field} must be {max_len} characters or less.")
        return False
    if any(c in s for c in ['"', ";"]):
        st.error(f'{field} cannot contain quotes or semicolons.')
        return False
    return True

# -------------------------------
# Org-scoped CRUD helpers
# -------------------------------
def current_org() -> Optional[str]:
    return st.session_state.get("organization")

def upsert_supplier(name: str, phone: Optional[str], email: Optional[str]) -> int:
    if not validate_text_input(name, 100, "Supplier name"):
        raise ValueError("Invalid supplier name")
    org = current_org()
    if not org:
        raise PermissionError("Login required.")
    with db_session() as conn:
        cur = conn.cursor()
        row = cur.execute("SELECT supplier_id FROM suppliers WHERE organization=? AND name=?;", (org, name)).fetchone()
        if row:
            supplier_id = row["supplier_id"]
            cur.execute("UPDATE suppliers SET phone=?, email=? WHERE supplier_id=?;", (phone, email, supplier_id))
        else:
            cur.execute("INSERT INTO suppliers (organization, name, phone, email, created_at) VALUES (?,?,?,?,?);",
                        (org, name, phone, email, get_now_iso()))
            supplier_id = cur.lastrowid
        log_audit("upsert_supplier", f"name={name}, id={supplier_id}")
        return supplier_id

def upsert_product(
    sku: str, name: str, category: str, supplier_name: str,
    cost_price: float, sell_price: float, qty: int, reorder_level: int
) -> int:
    org = current_org()
    if not org:
        raise PermissionError("Login required.")
    if not (validate_text_input(sku, 60, "SKU") and validate_text_input(name, 150, "Product name")):
        raise ValueError("Invalid product inputs")
    if category and not validate_text_input(category, 60, "Category"):
        raise ValueError("Invalid category")
    if supplier_name and not validate_text_input(supplier_name, 100, "Supplier"):
        raise ValueError("Invalid supplier")
    if min(cost_price, sell_price, qty, reorder_level) < 0:
        st.error("Prices and quantities must be non-negative.")
        raise ValueError("Invalid numerical inputs")

    supplier_id = None
    if supplier_name:
        supplier_id = upsert_supplier(supplier_name, None, None)

    with db_session() as conn:
        cur = conn.cursor()
        row = cur.execute("SELECT product_id FROM products WHERE organization=? AND sku=?;", (org, sku)).fetchone()
        if row:
            product_id = row["product_id"]
            cur.execute("""
                UPDATE products
                SET name=?, category=?, supplier_id=?, cost_price=?, sell_price=?, qty=?, reorder_level=?
                WHERE product_id=? AND organization=?;
            """, (name, category, supplier_id, cost_price, sell_price, qty, reorder_level, product_id, org))
        else:
            cur.execute("""
                INSERT INTO products (organization, sku, name, category, supplier_id, cost_price, sell_price, qty, reorder_level, created_at)
                VALUES (?,?,?,?,?,?,?,?,?,?);
            """, (org, sku, name, category, supplier_id, cost_price, sell_price, qty, reorder_level, get_now_iso()))
            product_id = cur.lastrowid
        log_audit("upsert_product", f"sku={sku}, id={product_id}")
        return product_id

def products_df(page:int=1, page_size:int=50, for_search=False) -> pd.DataFrame:
    org = current_org()
    if not org:
        return pd.DataFrame()
    offset = (page-1)*page_size
    q = """
        SELECT p.product_id, p.sku, p.name, p.category,
               (SELECT name FROM suppliers s WHERE s.supplier_id=p.supplier_id) as supplier,
               p.cost_price, p.sell_price, p.qty, p.reorder_level, p.created_at
        FROM products p
        WHERE p.organization=?
    """
    params = [org]
    if not for_search:
        q += " ORDER BY p.created_at DESC LIMIT ? OFFSET ?"
        params.extend([page_size, offset])
    return fetch_df(q, tuple(params))

def transactions_df(days: Optional[int]=None, product_id: Optional[int]=None) -> pd.DataFrame:
    org = current_org()
    if not org:
        return pd.DataFrame()
    q = """
        SELECT t.txn_id, t.product_id, p.sku, p.name, t.type, t.quantity, t.amount, t.note, t.created_at
        FROM transactions t
        JOIN products p ON p.product_id = t.product_id
        WHERE t.organization = ?
    """
    params = [org]
    conds = []
    if product_id:
        conds.append("t.product_id=?")
        params.append(product_id)
    if days:
        since = (datetime.utcnow() - timedelta(days=days)).isoformat(timespec="seconds")
        conds.append("t.created_at >= ?")
        params.append(since)
    if conds:
        q += " AND " + " AND ".join(conds)
    q += " ORDER BY t.created_at DESC;"
    return fetch_df(q, tuple(params))

def calc_kpis(currency:str="GH₵") -> dict:
    org = current_org()
    if not org:
        return dict(total_skus=0, stock_value=f"{currency} 0.00", low_stock=0, sales_rev_30d=f"{currency} 0.00")
    prods = fetch_df("""SELECT product_id, sku, name, category, cost_price, sell_price, qty, reorder_level
                        FROM products WHERE organization=?""", (org,))
    tx30 = transactions_df(30)
    total_skus = len(prods)
    stock_value = float((prods["qty"]*prods["cost_price"]).sum()) if not prods.empty else 0.0
    low_stock = int((prods["qty"] <= prods["reorder_level"]).sum()) if not prods.empty else 0
    sales_rev_30d = float(tx30[tx30["type"]=="sale"]["amount"].sum()) if not tx30.empty else 0.0
    return dict(
        total_skus=total_skus,
        stock_value=f"{currency} {stock_value:,.2f}",
        low_stock=low_stock,
        sales_rev_30d=f"{currency} {sales_rev_30d:,.2f}",
    )

def to_csv_download(df: pd.DataFrame, prefix: str) -> Tuple[bytes, str]:
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    csv = df.to_csv(index=False).encode("utf-8")
    return csv, f"{prefix}_{timestamp}.csv"

# -------------------------------
# Transactions (with negative-stock guard)
# -------------------------------
def add_transaction(product_id:int, ttype:str, quantity:int, amount:float=0.0, note:str=""):
    org = current_org()
    if not org:
        raise PermissionError("Login required.")
    prod = fetch_df("SELECT qty FROM products WHERE product_id=? AND organization=?;", (product_id, org))
    if prod.empty:
        st.error("Product not found.")
        return
    current_qty = int(prod["qty"].iloc[0])

    prevent_negative = st.session_state.get("prevent_negative_stock", True)
    if prevent_negative:
        if ttype == "sale" and quantity > current_qty:
            st.error(f"Cannot process sale of {quantity}. Only {current_qty} in stock.")
            return
        if ttype == "adjustment" and quantity < 0 and abs(quantity) > current_qty:
            st.error(f"Cannot adjust by {quantity}. Only {current_qty} in stock.")
            return

    if ttype == "sale":
        run_query("UPDATE products SET qty = qty - ? WHERE product_id=? AND organization=?;", (quantity, product_id, org))
    elif ttype in ("restock", "adjustment"):
        run_query("UPDATE products SET qty = qty + ? WHERE product_id=? AND organization=?;", (quantity, product_id, org))

    run_query("""INSERT INTO transactions (organization, product_id, type, quantity, amount, note, created_at)
                 VALUES (?,?,?,?,?,?,?);""",
              (org, product_id, ttype, quantity, amount, note, get_now_iso()))
    log_audit("add_transaction", f"type={ttype}, pid={product_id}, qty={quantity}, amt={amount}")

# -------------------------------
# DEMO MODE data (public preview)
# -------------------------------
def get_demo_products():
    return pd.DataFrame([
        dict(sku="SKU-001", name="Bottled Water 500ml", category="Drinks", supplier="AquaPlus Ltd", cost_price=1.5, sell_price=2.5, qty=120, reorder_level=30, created_at=get_now_iso()),
        dict(sku="SKU-002", name="Bottled Water 1.5L", category="Drinks", supplier="AquaPlus Ltd", cost_price=3.0, sell_price=5.0, qty=80, reorder_level=20, created_at=get_now_iso()),
        dict(sku="SKU-101", name="Rice 5kg", category="Groceries", supplier="FreshFoods Co", cost_price=60.0, sell_price=85.0, qty=40, reorder_level=10, created_at=get_now_iso()),
    ])

def get_demo_tx():
    now = datetime.utcnow()
    rows = []
    def row(sku, name, ttype, q, amt, days):
        return dict(txn_id=len(rows)+1, product_id=0, sku=sku, name=name, type=ttype,
                    quantity=q, amount=amt, note="Demo", created_at=(now - timedelta(days=days)).isoformat(timespec="seconds"))
    rows.append(row("SKU-001","Bottled Water 500ml","sale",10,25.0, 7))
    rows.append(row("SKU-001","Bottled Water 500ml","sale",12,30.0, 2))
    rows.append(row("SKU-101","Rice 5kg","restock",10,600.0, 14))
    return pd.DataFrame(rows)

# -------------------------------
# Sidebar — Auth & Navigation
# -------------------------------
st.sidebar.title("📦 InvyPro")

if not st.session_state.authenticated:
    with st.sidebar.expander("🔐 Login", expanded=True):
        u = st.text_input("Username")
        p = st.text_input("Password", type="password")
        if st.button("Login"):
            login(u, p)

    with st.sidebar.expander("✨ Create account"):
        su = st.text_input("New username")
        se = st.text_input("Email (optional)")
        so = st.text_input("Organization (unique name)")
        sp = st.text_input("Password", type="password")
        if st.button("Sign up"):
            signup(su, se, sp, so)

else:
    st.sidebar.success(f"Logged in as @{st.session_state.username} — {st.session_state.organization}")
    if st.button("Logout"):
        logout()

page = st.sidebar.radio(
    "Navigate",
    ["Dashboard", "Products", "Sales & Restock", "Suppliers", "Transactions", "Stock History", "Bulk Upload / Export", "Settings"],
)

# -------------------------------
# Helpers for gated UI
# -------------------------------
def require_auth_warning():
    st.warning("You’re in public preview. Please **log in** to manage your own inventory.")
def is_admin():
    return st.session_state.get("authenticated", False) and st.session_state.get("role") in ("admin","manager","staff")

# -------------------------------
# PAGES
# -------------------------------

# Dashboard
if page == "Dashboard":
    if st.session_state.demo_mode:
        st.markdown('<div class="hero"><h1>InvyPro — Fast, secure, beautiful inventory tracking</h1><p class="muted">Sign in or create an account to manage your own private stock. Below is a live demo preview.</p></div>', unsafe_allow_html=True)
        prods = get_demo_products()
        tx90 = get_demo_tx()
    else:
        prods = fetch_df("""SELECT sku, name, category, (SELECT name FROM suppliers s WHERE s.supplier_id=p.supplier_id) as supplier,
                                   cost_price, sell_price, qty, reorder_level, created_at
                            FROM products p WHERE organization=? ORDER BY created_at DESC;""",
                         (current_org(),))
        tx90 = transactions_df(90)

    # KPIs
    if st.session_state.demo_mode:
        kpis = dict(total_skus=len(prods), stock_value=f"{st.session_state.currency} {(prods['qty']*prods['cost_price']).sum():,.2f}",
                    low_stock=int((prods['qty']<=prods['reorder_level']).sum()), sales_rev_30d=f"{st.session_state.currency} {tx90[tx90['type']=='sale']['amount'].sum():,.2f}")
    else:
        kpis = calc_kpis(st.session_state.currency)

    c1, c2, c3, c4 = st.columns(4)
    with c1:
        st.markdown(f'<div class="report-card"><div class="small-label">Total SKUs</div><div class="big-num">{kpis["total_skus"]}</div></div>', unsafe_allow_html=True)
    with c2:
        st.markdown(f'<div class="report-card"><div class="small-label">Stock Value</div><div class="big-num">{kpis["stock_value"]}</div></div>', unsafe_allow_html=True)
    with c3:
        b = "badge low" if kpis["low_stock"]>0 else "badge ok"
        t = "Action needed" if kpis["low_stock"]>0 else "All good"
        st.markdown(f'<div class="report-card"><div class="small-label">Low-Stock Items</div><div class="big-num">{kpis["low_stock"]}</div><div class="{b}">{t}</div></div>', unsafe_allow_html=True)
    with c4:
        st.markdown(f'<div class="report-card"><div class="small-label">Sales (Last 30d)</div><div class="big-num">{kpis["sales_rev_30d"]}</div></div>', unsafe_allow_html=True)

    st.divider()

    # Charts
    sales = pd.DataFrame()
    if not tx90.empty:
        sales = tx90[tx90["type"] == "sale"].copy()
        sales["date"] = pd.to_datetime(sales["created_at"]).dt.date

    if not sales.empty:
        trend = sales.groupby("date", as_index=False)["amount"].sum()
        chart = alt.Chart(trend).mark_line(point=True).encode(
            x="date:T", y=alt.Y("amount:Q", title=f"Revenue ({st.session_state.currency})"),
            tooltip=["date:T", alt.Tooltip("amount:Q", format=",.2f")]
        ).properties(height=320, title="Sales Revenue — Last 90 Days")
        st.altair_chart(chart, use_container_width=True)
    else:
        st.info("No sales data yet.")

    cols = st.columns(2)
    with cols[0]:
        if not sales.empty:
            top = sales.groupby(["sku","name"], as_index=False)\
                       .agg(qty=("quantity","sum"), revenue=("amount","sum"))\
                       .sort_values("revenue", ascending=False).head(10)
            st.subheader("🏆 Top 10 Products (by revenue, 90d)")
            st.dataframe(top, use_container_width=True, hide_index=True)
        else:
            st.info("No top-seller data yet.")
    with cols[1]:
        if not prods.empty and "category" in prods.columns:
            cat = prods.groupby("category", as_index=False).agg(total_qty=("qty","sum"))
            if not cat.empty:
                pie = alt.Chart(cat).mark_arc(innerRadius=50).encode(
                    theta="total_qty:Q", color="category:N", tooltip=["category:N","total_qty:Q"]
                ).properties(height=320, title="Stock by Category")
                st.altair_chart(pie, use_container_width=True)
            else:
                st.info("Add categories to products to visualize distribution.")
        else:
            st.info("Add products with categories to see distribution.")

    st.subheader("🔔 Low-Stock Alerts")
    if not prods.empty:
        lowdf = prods[prods["qty"] <= prods.get("reorder_level", 0)]
        if lowdf.empty:
            st.success("No low-stock items.")
        else:
            st.dataframe(lowdf[["sku","name","qty","reorder_level"]], use_container_width=True, hide_index=True)
    else:
        st.info("No products yet — add products on the Products page.")

# Products
elif page == "Products":
    st.header("🧾 Products")
    if st.session_state.demo_mode:
        require_auth_warning()

    with st.expander("➕ Add / Edit Product"):
        sku = st.text_input("SKU *")
        name = st.text_input("Name *")
        colA, colB, colC = st.columns(3)
        with colA: category = st.text_input("Category")
        with colB: supplier_name = st.text_input("Supplier")
        with colC: reorder_level = st.number_input("Reorder Level", 0, 10**9, 0, step=1)
        col1, col2, col3 = st.columns(3)
        with col1: cost_price = st.number_input("Cost Price", 0.0, 10**12, 0.0, step=0.01, format="%.2f")
        with col2: sell_price = st.number_input("Sell Price", 0.0, 10**12, 0.0, step=0.01, format="%.2f")
        with col3: qty = st.number_input("Initial Quantity", 0, 10**9, 0, step=1)

        disabled = not is_admin() or st.session_state.demo_mode
        if st.button("Save Product", type="primary", disabled=disabled):
            try:
                pid = upsert_product(
                    sku.strip(), name.strip(), category.strip(), supplier_name.strip(),
                    float(cost_price), float(sell_price), int(qty), int(reorder_level)
                )
                st.success(f"Saved product (ID: {pid}).")
                st.experimental_rerun()
            except PermissionError:
                require_auth_warning()
            except ValueError:
                pass

    st.subheader("📄 Product List")
    q = st.text_input("Search (SKU / Name / Category)")
    page_num = st.number_input("Page", min_value=1, value=1, step=1)
    page_size = 50

    if st.session_state.demo_mode:
        all_products = get_demo_products()
    else:
        all_products = fetch_df("""
            SELECT p.product_id, p.sku, p.name, p.category,
                   (SELECT name FROM suppliers s WHERE s.supplier_id=p.supplier_id) as supplier,
                   p.cost_price, p.sell_price, p.qty, p.reorder_level, p.created_at
            FROM products p WHERE p.organization=? ORDER BY p.created_at DESC;
        """, (current_org(),))

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

    # Delete
    if not st.session_state.demo_mode and is_admin() and not df_page.empty:
        st.markdown('<div class="block-space"></div>', unsafe_allow_html=True)
        del_sku = st.selectbox("Delete product by SKU", options=["-- select --"] + df_page["sku"].astype(str).tolist())
        if st.button("Delete", type="secondary") and del_sku != "-- select --":
            run_query("DELETE FROM products WHERE sku=? AND organization=?;", (del_sku, current_org()))
            log_audit("delete_product", f"sku={del_sku}")
            st.warning(f"Deleted product SKU {del_sku}")
            st.experimental_rerun()

# Sales & Restock
elif page == "Sales & Restock":
    st.header("🧾 Sales & Restock")
    if st.session_state.demo_mode:
        require_auth_warning()
    if st.session_state.demo_mode:
        products = get_demo_products()
        st.info("Demo list only — login to record real transactions.")
    else:
        products = fetch_df("SELECT product_id, sku, name, sell_price, cost_price, qty FROM products WHERE organization=? ORDER BY name;", (current_org(),))

    if products.empty:
        st.info("No products yet — add some on the Products page.")
    else:
        if st.session_state.demo_mode:
            opts = [f"{r['sku']} — {r['name']}" for _, r in products.iterrows()]
            _ = st.selectbox("Select product", options=opts)
            st.info("Recording is disabled in demo mode.")
        else:
            sku_map = {f"{r['sku']} — {r['name']}": (int(r["product_id"]), float(r["sell_price"]), float(r["cost_price"])) for _, r in products.iterrows()}
            pick = st.selectbox("Select product", options=list(sku_map.keys()))
            pid, sell_price, cost_price = sku_map[pick]
            col1, col2 = st.columns(2)
            with col1:
                ttype = st.selectbox("Transaction Type", options=["sale", "restock", "adjustment"])
            with col2:
                qty = st.number_input("Quantity" + (" (use negative to subtract)" if ttype=="adjustment" else ""), value=1 if ttype!="adjustment" else 0, step=1, min_value=None if ttype=="adjustment" else 1)
            note = st.text_input("Note (optional)")

            if ttype == "sale":
                default_amt = sell_price * qty
            elif ttype == "restock":
                default_amt = cost_price * qty
            else:
                default_amt = 0.0
            amt = st.number_input(f"Amount ({st.session_state.currency})", value=float(default_amt), step=0.01, format="%.2f")

            if st.button("Record Transaction", type="primary", disabled=not is_admin()):
                if ttype in ("sale","restock") and qty <= 0:
                    st.error("Quantity must be positive for sale/restock.")
                else:
                    add_transaction(pid, ttype, int(qty), float(amt), note)
                    st.success(f"{ttype.capitalize()} recorded.")
                    st.experimental_rerun()

        st.divider()
        st.subheader("Recent Transactions (last 14 days)")
        if st.session_state.demo_mode:
            tx = get_demo_tx()
        else:
            tx = transactions_df(14)
        st.dataframe(tx, use_container_width=True, hide_index=True)

# Suppliers
elif page == "Suppliers":
    st.header("🤝 Suppliers")
    if st.session_state.demo_mode:
        require_auth_warning()

    sname = st.text_input("Supplier Name *")
    sphone = st.text_input("Phone")
    semail = st.text_input("Email")
    if st.button("Save Supplier", type="primary", disabled=st.session_state.demo_mode or not is_admin()):
        try:
            sid = upsert_supplier(sname.strip(), sphone.strip(), semail.strip())
            st.success(f"Saved supplier (ID: {sid}).")
            st.experimental_rerun()
        except PermissionError:
            require_auth_warning()
        except ValueError:
            pass

    if st.session_state.demo_mode:
        st.info("Demo mode — supplier list hidden.")
    else:
        sups = fetch_df("SELECT supplier_id, name, phone, email FROM suppliers WHERE organization=? ORDER BY name;", (current_org(),))
        st.subheader("Supplier List")
        st.dataframe(sups, use_container_width=True, hide_index=True)

        if is_admin() and not sups.empty:
            del_supplier = st.selectbox("Delete supplier by name", options=["-- select --"] + sups["name"].tolist())
            if st.button("Delete Supplier", type="secondary") and del_supplier != "-- select --":
                run_query("DELETE FROM suppliers WHERE organization=? AND name=?;", (current_org(), del_supplier))
                log_audit("delete_supplier", f"name={del_supplier}")
                st.warning(f"Deleted supplier {del_supplier}")
                st.experimental_rerun()

# Transactions
elif page == "Transactions":
    st.header("📜 All Transactions")
    if st.session_state.demo_mode:
        tx = get_demo_tx()
        require_auth_warning()
    else:
        tx = transactions_df()
    if tx.empty:
        st.info("No transactions yet.")
    else:
        c1, c2, c3 = st.columns(3)
        with c1:
            f_type = st.selectbox("Type filter", options=["All","sale","restock","adjustment"])
        with c2:
            start = st.date_input("Start date", value=datetime.utcnow().date() - timedelta(days=30))
        with c3:
            end = st.date_input("End date", value=datetime.utcnow().date())
        fdf = tx.copy()
        fdf["dt"] = pd.to_datetime(fdf["created_at"])
        tz = pytz.timezone(st.session_state.timezone)
        start_ts = pd.Timestamp(start).tz_localize(tz)
        end_ts = pd.Timestamp(end).tz_localize(tz) + pd.Timedelta(days=1)
        fdf = fdf[(fdf["dt"] >= start_ts) & (fdf["dt"] < end_ts)]
        if f_type != "All":
            fdf = fdf[fdf["type"] == f_type]
        st.dataframe(fdf.drop(columns=["dt"]), use_container_width=True, hide_index=True)
        if not st.session_state.demo_mode:
            csv, fname = to_csv_download(fdf.drop(columns=["dt"]), f"transactions_{start}_to_{end}")
            st.download_button("Download CSV", data=csv, file_name=fname, mime="text/csv")

# Stock History
elif page == "Stock History":
    st.header("📈 Stock History")
    if st.session_state.demo_mode:
        require_auth_warning()
        st.info("Login to view and chart your stock history.")
    else:
        prods = fetch_df("SELECT sku, product_id, name FROM products WHERE organization=? ORDER BY name;", (current_org(),))
        if prods.empty:
            st.info("No products yet.")
        else:
            sku = st.selectbox("Select product", options=["-- select --"] + prods["sku"].tolist())
            if sku != "-- select --":
                pid = int(prods[prods["sku"]==sku]["product_id"].iloc[0])
                tx = transactions_df(product_id=pid)
                if tx.empty:
                    st.info("No transactions for this product.")
                else:
                    tx["date"] = pd.to_datetime(tx["created_at"]).dt.date
                    tx["stock_change"] = tx.apply(lambda r: -r["quantity"] if r["type"]=="sale" else r["quantity"], axis=1)
                    chart = alt.Chart(tx).mark_line(point=True).encode(
                        x="date:T", y="stock_change:Q", color="type:N", tooltip=["date:T","type:N","quantity:Q"]
                    ).properties(height=300, title=f"Stock Changes for {sku}")
                    st.altair_chart(chart, use_container_width=True)
                    st.dataframe(tx[["sku","name","type","quantity","amount","note","created_at"]], use_container_width=True, hide_index=True)

# Bulk Upload / Export
elif page == "Bulk Upload / Export":
    st.header("📥 Bulk Upload / Export")
    if st.session_state.demo_mode:
        require_auth_warning()
        st.stop()

    st.subheader("Upload Products CSV")
    st.caption("Columns: sku, name, category, supplier, cost_price, sell_price, qty, reorder_level")
    up = st.file_uploader("Choose product CSV", type=["csv"])
    if up and is_admin():
        df = pd.read_csv(up)
        required = {"sku","name"}
        if not required.issubset(df.columns):
            st.error("CSV must include at least: sku, name.")
        else:
            count, errors = 0, []
            for i, r in df.fillna("").iterrows():
                try:
                    upsert_product(
                        str(r.get("sku","")).strip(),
                        str(r.get("name","")).strip(),
                        str(r.get("category","")).strip(),
                        str(r.get("supplier","")).strip(),
                        float(r.get("cost_price",0) or 0),
                        float(r.get("sell_price",0) or 0),
                        int(r.get("qty",0) or 0),
                        int(r.get("reorder_level",0) or 0),
                    )
                    count += 1
                except Exception as e:
                    errors.append(f"Row {i+2}: {str(e)}")
            st.success(f"Upserted {count} products.")
            if errors:
                err_csv = pd.DataFrame(errors, columns=["error"]).to_csv(index=False).encode("utf-8")
                st.download_button("Download Error Report", data=err_csv, file_name="product_upload_errors.csv", mime="text/csv")
            st.experimental_rerun()

    st.divider()
    st.subheader("Upload Transactions CSV")
    st.caption("Columns: sku, type (sale/restock/adjustment), quantity, amount (optional), note (optional)")
    up2 = st.file_uploader("Choose transactions CSV", type=["csv"], key="tx_upload")
    if up2 and is_admin():
        df2 = pd.read_csv(up2)
        required2 = {"sku","type","quantity"}
        if not required2.issubset(df2.columns):
            st.error("CSV must include: sku, type, quantity.")
        else:
            products = fetch_df("SELECT sku, product_id FROM products WHERE organization=?;", (current_org(),))
            sku_to_pid = dict(zip(products["sku"], products["product_id"]))
            ok, fail, errors = 0, 0, []
            for i, r in df2.fillna("").iterrows():
                sku = str(r.get("sku","")).strip()
                pid = sku_to_pid.get(sku)
                ttype = str(r.get("type","")).strip().lower()
                qty = r.get("quantity","")
                amt = float(r.get("amount",0) or 0)
                note = str(r.get("note",""))
                if not pid:
                    errors.append(f"Row {i+2}: Invalid SKU '{sku}'")
                    fail += 1; continue
                if ttype not in {"sale","restock","adjustment"}:
                    errors.append(f"Row {i+2}: Invalid type '{ttype}'")
                    fail += 1; continue
                try:
                    qty_i = int(qty)
                    if ttype in ("sale","restock") and qty_i < 1:
                        errors.append(f"Row {i+2}: Quantity must be positive")
                        fail += 1; continue
                    add_transaction(pid, ttype, qty_i, amt, note)
                    ok += 1
                except Exception as e:
                    errors.append(f"Row {i+2}: {str(e)}"); fail += 1
            st.success(f"Processed {ok} transactions. Skipped {fail}.")
            if errors:
                err_csv = pd.DataFrame(errors, columns=["error"]).to_csv(index=False).encode("utf-8")
                st.download_button("Download Transaction Errors", data=err_csv, file_name="transaction_upload_errors.csv", mime="text/csv")
            st.experimental_rerun()

    st.divider()
    st.subheader("Export Data")
    col1, col2, col3 = st.columns(3)
    with col1:
        prods = fetch_df("""
            SELECT sku, name, category,
                   (SELECT name FROM suppliers s WHERE s.supplier_id=p.supplier_id) as supplier,
                   cost_price, sell_price, qty, reorder_level, created_at
            FROM products p WHERE organization=? ORDER BY created_at DESC;
        """, (current_org(),))
        csv, name = to_csv_download(prods, "products_export")
        st.download_button("Download Products CSV", data=csv, file_name=name, mime="text/csv")
    with col2:
        tx = transactions_df()
        csv2, name2 = to_csv_download(tx, "transactions_export")
        st.download_button("Download Transactions CSV", data=csv2, file_name=name2, mime="text/csv")
    with col3:
        sups = fetch_df("SELECT name, phone, email, created_at FROM suppliers WHERE organization=? ORDER BY name;", (current_org(),))
        csv3, name3 = to_csv_download(sups, "suppliers_export")
        st.download_button("Download Suppliers CSV", data=csv3, file_name=name3, mime="text/csv")

# Settings
elif page == "Settings":
    st.header("⚙️ Settings & Info")
    st.markdown(
        """
**App:** InvyPro  
**Storage:** SQLite (file: `inventory_secure.db` by default)  
**Tables:** users, suppliers, products, transactions, audit_logs (all org-scoped)  
**Passwords:** PBKDF2-HMAC(SHA256) + constant-time compare  
**Isolation:** Every read/write filtered by `organization`  
        """
    )
    st.subheader("Preferences")
    tz_options = ["UTC", "Africa/Accra", "Europe/London", "America/New_York"]
    st.session_state.timezone = st.selectbox("Time Zone", tz_options,
        index=tz_options.index(st.session_state.timezone) if st.session_state.timezone in tz_options else 0)
    currency_options = ["GH₵", "USD $", "EUR €", "GBP £"]
    st.session_state.currency = st.selectbox("Currency", currency_options,
        index=currency_options.index(st.session_state.currency) if st.session_state.currency in currency_options else 0)
    st.session_state.prevent_negative_stock = st.checkbox(
        "Prevent negative stock for sales & negative adjustments", value=st.session_state.prevent_negative_stock
    )

    st.subheader("Demo Data (for your org)")
    if st.button("Load Sample Data"):
        if not is_admin() or st.session_state.demo_mode:
            require_auth_warning()
        else:
            # Insert sample suppliers & products for this org
            try:
                upsert_supplier("AquaPlus Ltd", "020-000-0001", "orders@aquaplus.com")
                upsert_supplier("FreshFoods Co", "020-000-0002", "hello@freshfoods.com")
                upsert_product("SKU-001","Bottled Water 500ml","Drinks","AquaPlus Ltd",1.5,2.5,120,30)
                upsert_product("SKU-002","Bottled Water 1.5L","Drinks","AquaPlus Ltd",3.0,5.0,80,20)
                upsert_product("SKU-101","Rice 5kg","Groceries","FreshFoods Co",60.0,85.0,40,10)
                pid_df = fetch_df("SELECT sku, product_id FROM products WHERE organization=?;", (current_org(),))
                sku2pid = dict(zip(pid_df["sku"], pid_df["product_id"]))
                add_transaction(sku2pid["SKU-001"], "sale", 10, 25.0, "Opening day")
                add_transaction(sku2pid["SKU-001"], "sale", 15, 37.5, "Walk-ins")
                add_transaction(sku2pid["SKU-101"], "restock", 10, 600.0, "Weekly restock")
                add_transaction(sku2pid["SKU-002"], "sale", 5, 25.0, "Quick sale")
                log_audit("load_demo_data", "Sample data loaded")
                st.success("Sample data loaded for your organization.")
                st.experimental_rerun()
            except PermissionError:
                require_auth_warning()

    st.subheader("Danger Zone")
    st.caption("Use with extreme care. Your organization only.")
    if st.button("Reset My Organization (delete all my data)"):
        if not is_admin() or st.session_state.demo_mode:
            require_auth_warning()
        else:
            org = current_org()
            run_query("DELETE FROM transactions WHERE organization=?;", (org,))
            run_query("DELETE FROM products WHERE organization=?;", (org,))
            run_query("DELETE FROM suppliers WHERE organization=?;", (org,))
            run_query("DELETE FROM audit_logs WHERE organization=?;", (org,))
            log_audit("reset_database", "All data cleared for org")
            st.warning("Your organization's data has been cleared.")
            st.experimental_rerun()
