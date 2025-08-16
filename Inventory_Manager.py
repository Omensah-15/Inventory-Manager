"""
InvyPro — Inventory Manager (Single-file Streamlit app)

Features:
- SQLite persistence (products + transactions + suppliers + audit_logs)
- Add / Edit / Delete products and suppliers
- Sales & Restock transactions (auto stock updates, negative stock prevention)
- Bulk CSV upload (products & transactions), CSV export with timestamps
- Low-stock alerts, SKU search, filters, pagination
- Dashboard KPIs + charts (sales trend, best sellers, stock by category)
- Session-based authentication (env password, secure compare)
- Time zone and currency support
- Audit trail for admin actions
- Clean UI with custom CSS; one-file deployment
"""

import os
import io
import time
import sqlite3
import hmac
from contextlib import contextmanager
from datetime import datetime, timedelta
from typing import Optional, Tuple

import pandas as pd
import streamlit as st
import altair as alt
import pytz

# -------------------------------
# App meta & dependencies info
# -------------------------------
st.set_page_config(
    page_title="InvyPro — Inventory Manager",
    page_icon="📦",
    layout="wide",
    initial_sidebar_state="expanded",
)

# -------------------------------
# Minimal CSS for polish
# -------------------------------
st.markdown(
    """
    <style>
    /* Container and cards */
    .report-card {border:1px solid #eef2f6;border-radius:10px;padding:12px;margin-bottom:8px;background:#fff;}
    .small-label {font-size:0.85rem;color:#6b7280;margin-bottom:0.25rem;}
    .big-num {font-size:1.4rem;font-weight:700;margin:0;color:#0f172a;}
    .badge {display:inline-block;padding:5px 10px;border-radius:999px;background:#f1f5f9;font-size:0.78rem;margin-top:6px;}
    .low {background:#fff1f2;color:#861b1b;}
    .ok {background:#ecfeff;color:#035b6a;}
    .muted {color:#6b7280;font-size:0.9rem;}
    .block-space {margin-top:0.6rem;margin-bottom:0.6rem;}
    .danger {background:#fff7ed;color:#7a3419;padding:6px;border-radius:6px;}
    </style>
    """,
    unsafe_allow_html=True,
)

# -------------------------------
# Database utilities (SQLite)
# -------------------------------
DB_PATH = os.getenv("INVYPRO_DB", "inventory.db")
_conn = None


def get_conn():
    """Return a single sqlite3 connection for app lifetime."""
    global _conn
    if _conn is None:
        _conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        _conn.execute("PRAGMA foreign_keys = ON;")
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
    """Create tables if they don't exist."""
    with db_session() as conn:
        cur = conn.cursor()
        cur.execute(
            """
        CREATE TABLE IF NOT EXISTS suppliers (
            supplier_id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            phone TEXT,
            email TEXT
        );"""
        )
        cur.execute(
            """
        CREATE TABLE IF NOT EXISTS products (
            product_id INTEGER PRIMARY KEY AUTOINCREMENT,
            sku TEXT NOT NULL UNIQUE,
            name TEXT NOT NULL,
            category TEXT,
            supplier_id INTEGER,
            cost_price REAL DEFAULT 0,
            sell_price REAL DEFAULT 0,
            qty INTEGER DEFAULT 0,
            reorder_level INTEGER DEFAULT 0,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(supplier_id) REFERENCES suppliers(supplier_id) ON DELETE SET NULL
        );"""
        )
        cur.execute(
            """
        CREATE TABLE IF NOT EXISTS transactions (
            txn_id INTEGER PRIMARY KEY AUTOINCREMENT,
            product_id INTEGER NOT NULL,
            type TEXT NOT NULL CHECK(type IN ('sale','restock','adjustment')),
            quantity INTEGER NOT NULL,
            amount REAL DEFAULT 0,
            note TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(product_id) REFERENCES products(product_id) ON DELETE CASCADE
        );"""
        )
        cur.execute(
            """
        CREATE TABLE IF NOT EXISTS audit_logs (
            log_id INTEGER PRIMARY KEY AUTOINCREMENT,
            action TEXT NOT NULL,
            details TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );"""
        )


init_db()

# -------------------------------
# Helper functions
# -------------------------------


def get_current_time() -> str:
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


def log_audit(action: str, details: str):
    run_query(
        "INSERT INTO audit_logs (action, details, created_at) VALUES (?,?,?);",
        (action, details, get_current_time()),
    )


def validate_text_input(s: str, max_len: int, field: str) -> bool:
    if not s:
        st.error(f"{field} is required.")
        return False
    if len(s) > max_len:
        st.error(f"{field} must be {max_len} characters or less.")
        return False
    # prevent basic injection characters in free text fields
    if any(c in s for c in ['"', ";"]):
        st.error(f'{field} cannot contain quotes or semicolons.')
        return False
    return True


def upsert_supplier(name: str, phone: Optional[str], email: Optional[str]) -> int:
    if not validate_text_input(name, 100, "Supplier name"):
        raise ValueError("Invalid supplier name")
    with db_session() as conn:
        cur = conn.cursor()
        cur.execute("SELECT supplier_id FROM suppliers WHERE name = ?;", (name,))
        row = cur.fetchone()
        if row:
            supplier_id = row[0]
            cur.execute("UPDATE suppliers SET phone = ?, email = ? WHERE supplier_id = ?;", (phone, email, supplier_id))
        else:
            cur.execute("INSERT INTO suppliers (name, phone, email) VALUES (?,?,?);", (name, phone, email))
            supplier_id = cur.lastrowid
        log_audit("upsert_supplier", f"name={name}, id={supplier_id}")
        return supplier_id


def upsert_product(
    sku: str,
    name: str,
    category: str,
    supplier_name: str,
    cost_price: float,
    sell_price: float,
    qty: int,
    reorder_level: int,
) -> int:
    if not (validate_text_input(sku, 50, "SKU") and validate_text_input(name, 150, "Product name")):
        raise ValueError("Invalid product inputs")
    if category and not validate_text_input(category, 50, "Category"):
        raise ValueError("Invalid category")
    if supplier_name and not validate_text_input(supplier_name, 100, "Supplier"):
        raise ValueError("Invalid supplier")
    if cost_price < 0 or sell_price < 0 or qty < 0 or reorder_level < 0:
        st.error("Prices and quantities must be non-negative.")
        raise ValueError("Invalid numerical inputs")

    supplier_id = None
    if supplier_name:
        supplier_id = upsert_supplier(supplier_name, None, None)

    with db_session() as conn:
        cur = conn.cursor()
        cur.execute("SELECT product_id FROM products WHERE sku = ?;", (sku,))
        row = cur.fetchone()
        if row:
            product_id = row[0]
            cur.execute(
                """
                UPDATE products
                SET name=?, category=?, supplier_id=?, cost_price=?, sell_price=?, qty=?, reorder_level=?
                WHERE product_id=?;
            """,
                (name, category, supplier_id, cost_price, sell_price, qty, reorder_level, product_id),
            )
        else:
            cur.execute(
                """
                INSERT INTO products (sku, name, category, supplier_id, cost_price, sell_price, qty, reorder_level)
                VALUES (?,?,?,?,?,?,?,?);
            """,
                (sku, name, category, supplier_id, cost_price, sell_price, qty, reorder_level),
            )
            product_id = cur.lastrowid
        log_audit("upsert_product", f"sku={sku}, id={product_id}")
        return product_id


def get_products_df(page: int = 1, page_size: int = 50, product_id: Optional[int] = None) -> pd.DataFrame:
    offset = (page - 1) * page_size
    query = """
        SELECT p.product_id, p.sku, p.name, p.category, s.name as supplier, p.cost_price, p.sell_price,
               p.qty, p.reorder_level, p.created_at
        FROM products p
        LEFT JOIN suppliers s ON p.supplier_id = s.supplier_id
    """
    params = ()
    if product_id:
        query += " WHERE p.product_id = ?"
        params = (product_id,)
    else:
        query += " ORDER BY p.created_at DESC LIMIT ? OFFSET ?"
        params = (page_size, offset)
    return fetch_df(query, params)


def get_transactions_df(days: Optional[int] = None, product_id: Optional[int] = None) -> pd.DataFrame:
    query = """
        SELECT t.txn_id, t.product_id, p.sku, p.name, t.type, t.quantity, t.amount, t.note, t.created_at
        FROM transactions t
        JOIN products p ON p.product_id = t.product_id
    """
    params = []
    conds = []
    if product_id:
        conds.append("t.product_id = ?")
        params.append(product_id)
    if days:
        since = (datetime.utcnow() - timedelta(days=days)).isoformat(timespec="seconds")
        conds.append("t.created_at >= ?")
        params.append(since)
    if conds:
        query += " WHERE " + " AND ".join(conds)
    query += " ORDER BY t.created_at DESC;"
    return fetch_df(query, tuple(params))


def calc_kpis(currency: str = "GH₵") -> dict:
    # fetch all products for KPIs
    products = fetch_df(
        """
        SELECT p.product_id, p.sku, p.name, p.category, p.cost_price, p.sell_price, p.qty, p.reorder_level
        FROM products p
        """
    )
    txns_30 = get_transactions_df(30)

    total_skus = len(products)
    stock_value = float((products["qty"] * products["cost_price"]).sum()) if not products.empty else 0.0
    low_stock = int((products["qty"] <= products["reorder_level"]).sum()) if not products.empty else 0
    sales_rows = txns_30[txns_30["type"] == "sale"]
    sales_rev_30d = float(sales_rows["amount"].sum()) if not sales_rows.empty else 0.0
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
# Transaction logic with guards
# -------------------------------


def add_transaction(product_id: int, ttype: str, quantity: int, amount: float = 0.0, note: str = ""):
    # fetch single product row to check qty
    prod = get_products_df(page=1, page_size=1, product_id=product_id)
    if prod.empty:
        st.error("Product not found.")
        return
    current_qty = int(prod["qty"].iloc[0])

    prevent_negative = st.session_state.get("prevent_negative_stock", True)

    # Guard: prevent negative stock for sales and negative adjustments (if enabled)
    if prevent_negative:
        if ttype == "sale":
            if quantity > current_qty:
                st.error(f"Cannot process sale of {quantity}. Only {current_qty} in stock.")
                return
        elif ttype == "adjustment" and quantity < 0:
            if abs(quantity) > current_qty:
                st.error(f"Cannot adjust by {quantity}. Only {current_qty} in stock.")
                return

    # Apply stock movement
    if ttype == "sale":
        run_query("UPDATE products SET qty = qty - ? WHERE product_id = ?;", (quantity, product_id))
    elif ttype == "restock":
        run_query("UPDATE products SET qty = qty + ? WHERE product_id = ?;", (quantity, product_id))
    elif ttype == "adjustment":
        run_query("UPDATE products SET qty = qty + ? WHERE product_id = ?;", (quantity, product_id))

    # Insert transaction record
    run_query(
        """
        INSERT INTO transactions (product_id, type, quantity, amount, note, created_at)
        VALUES (?,?,?,?,?,?);
        """,
        (product_id, ttype, quantity, amount, note, get_current_time()),
    )
    log_audit("add_transaction", f"type={ttype}, pid={product_id}, qty={quantity}, amt={amount}")


# -------------------------------
# Authentication (env password)
# -------------------------------


def check_password(entered: str) -> bool:
    """
    Secure check:
     - If INVYPRO_ADMIN not set => open admin mode (True).
     - Otherwise use hmac.compare_digest for safe equals.
    """
    env_pwd = os.getenv("INVYPRO_ADMIN", "")
    if not env_pwd:
        return True
    # compare entered with env value using hmac for constant-time compare
    try:
        return hmac.compare_digest(entered or "", env_pwd)
    except Exception:
        return False


# -------------------------------
# Session defaults
# -------------------------------
if "authenticated" not in st.session_state:
    st.session_state.authenticated = False
if "timezone" not in st.session_state:
    st.session_state.timezone = "UTC"
if "currency" not in st.session_state:
    st.session_state.currency = "GH₵"
if "prevent_negative_stock" not in st.session_state:
    st.session_state.prevent_negative_stock = True

# -------------------------------
# Sidebar: login, navigation, settings
# -------------------------------
st.sidebar.title("📦 InvyPro")
with st.sidebar.expander("🔐 Admin Login", expanded=not st.session_state.authenticated):
    if not st.session_state.authenticated:
        pwd = st.text_input("Admin password", type="password", help="Set environment variable INVYPRO_ADMIN to require login.")
        if st.button("Login"):
            if check_password(pwd):
                st.session_state.authenticated = True
                log_audit("login", "admin logged in")
                st.experimental_rerun()
            else:
                st.error("Incorrect password.")
    else:
        st.success("Logged in as Admin")
        if st.button("Logout"):
            st.session_state.authenticated = False
            log_audit("logout", "admin logged out")
            st.experimental_rerun()

is_admin = st.session_state.authenticated

page = st.sidebar.radio(
    "Navigate",
    [
        "Dashboard",
        "Products",
        "Sales & Restock",
        "Suppliers",
        "Transactions",
        "Stock History",
        "Bulk Upload / Export",
        "Settings",
    ],
)

# -------------------------------
# Page: Dashboard
# -------------------------------
if page == "Dashboard":
    st.header("📊 Dashboard")
    kpis = calc_kpis(st.session_state.currency)
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        st.markdown(
            f'<div class="report-card"><div class="small-label">Total SKUs</div><div class="big-num">{kpis["total_skus"]}</div></div>',
            unsafe_allow_html=True,
        )
    with c2:
        st.markdown(
            f'<div class="report-card"><div class="small-label">Stock Value</div><div class="big-num">{kpis["stock_value"]}</div></div>',
            unsafe_allow_html=True,
        )
    with c3:
        badge_class = "badge low" if kpis["low_stock"] > 0 else "badge ok"
        st.markdown(
            f'<div class="report-card"><div class="small-label">Low-Stock Items</div><div class="big-num">{kpis["low_stock"]}</div><div class="{badge_class}">{"Action needed" if kpis["low_stock"]>0 else "All good"}</div></div>',
            unsafe_allow_html=True,
        )
    with c4:
        st.markdown(
            f'<div class="report-card"><div class="small-label">Sales (Last 30d)</div><div class="big-num">{kpis["sales_rev_30d"]}</div></div>',
            unsafe_allow_html=True,
        )

    st.divider()

    # Charts & insights
    products_all = fetch_df(
        """
        SELECT p.product_id, p.sku, p.name, p.category, p.qty, p.cost_price, p.sell_price
        FROM products p
        """
    )
    txns_90 = get_transactions_df(90)

    sales = pd.DataFrame()
    if not txns_90.empty:
        sales = txns_90[txns_90["type"] == "sale"].copy()
        sales["date"] = pd.to_datetime(sales["created_at"]).dt.date

    if not sales.empty:
        trend = sales.groupby("date", as_index=False)["amount"].sum()
        if len(trend) > 100:
            trend = trend.tail(100)
        chart = alt.Chart(trend).mark_line(point=True).encode(
            x="date:T", y=alt.Y("amount:Q", title=f"Revenue ({st.session_state.currency})"), tooltip=["date:T", alt.Tooltip("amount:Q", format=",.2f")]
        ).properties(height=320, title="Sales Revenue — Last 90 Days")
        st.altair_chart(chart, use_container_width=True)
    else:
        st.info("No sales data (last 90 days).")

    cols = st.columns(2)
    with cols[0]:
        if not sales.empty:
            top = sales.groupby(["sku", "name"], as_index=False).agg(qty=("quantity", "sum"), revenue=("amount", "sum")).sort_values("revenue", ascending=False).head(10)
            st.subheader("🏆 Top 10 Products (by revenue, 90d)")
            st.dataframe(top, use_container_width=True, hide_index=True)
        else:
            st.info("No top-seller data yet.")
    with cols[1]:
        if not products_all.empty and "category" in products_all.columns:
            cat = products_all.groupby("category", as_index=False).agg(total_qty=("qty", "sum"))
            if not cat.empty:
                pie = alt.Chart(cat).mark_arc(innerRadius=50).encode(theta="total_qty:Q", color="category:N", tooltip=["category:N", "total_qty:Q"]).properties(height=320, title="Stock by Category")
                st.altair_chart(pie, use_container_width=True)
            else:
                st.info("Add categories to products to visualize distribution.")
        else:
            st.info("Add products with categories to see distribution.")

    st.subheader("🔔 Low-Stock Alerts")
    if not products_all.empty:
        lowdf = products_all[products_all["qty"] <= products_all.get("reorder_level", 0)].copy() if "reorder_level" in products_all.columns else pd.DataFrame()
        # If initial fetch lacked reorder_level, run full fetch for low stock check:
        if lowdf.empty and fetch_df("SELECT 1 FROM products LIMIT 1").shape[0] > 0:
            # fallback accurate query
            lowdf = fetch_df("SELECT sku, name, qty, reorder_level FROM products WHERE qty <= reorder_level;")
        if lowdf.empty:
            st.success("No low-stock items.")
        else:
            st.dataframe(lowdf, use_container_width=True, hide_index=True)
    else:
        st.info("No products yet — add products on the Products page.")

# -------------------------------
# Page: Products
# -------------------------------
elif page == "Products":
    st.header("🧾 Products")
    with st.expander("➕ Add / Edit Product"):
        if not is_admin:
            st.warning("Login as admin to add or edit products.")
        sku = st.text_input("SKU *")
        name = st.text_input("Name *")
        colA, colB, colC = st.columns(3)
        with colA:
            category = st.text_input("Category")
        with colB:
            supplier_name = st.text_input("Supplier")
        with colC:
            reorder_level = st.number_input("Reorder Level", 0, 10**9, 0, step=1)
        col1, col2, col3 = st.columns(3)
        with col1:
            cost_price = st.number_input("Cost Price", 0.0, 10**12, 0.0, step=0.01, format="%.2f")
        with col2:
            sell_price = st.number_input("Sell Price", 0.0, 10**12, 0.0, step=0.01, format="%.2f")
        with col3:
            qty = st.number_input("Initial Quantity", 0, 10**9, 0, step=1)
        if st.button("Save Product", type="primary", disabled=not is_admin):
            try:
                pid = upsert_product(
                    sku.strip(), name.strip(), category.strip(), supplier_name.strip(), float(cost_price), float(sell_price), int(qty), int(reorder_level)
                )
                st.success(f"Saved product (ID: {pid}).")
                st.experimental_rerun()
            except ValueError:
                # validate_text_input already shows errors
                pass

    st.subheader("📄 Product List")
    q = st.text_input("Search (SKU / Name / Category)")
    page_num = st.number_input("Page", min_value=1, value=1, step=1)
    page_size = 50

    # Fetch all, filter, then paginate (search-before-pagination)
    all_products = fetch_df(
        """
        SELECT p.product_id, p.sku, p.name, p.category, s.name as supplier, p.cost_price, p.sell_price, p.qty, p.reorder_level, p.created_at
        FROM products p LEFT JOIN suppliers s ON p.supplier_id = s.supplier_id
        ORDER BY p.created_at DESC;
        """
    )
    filtered = all_products
    if q:
        ql = q.strip().lower()
        filtered = all_products[
            all_products.apply(
                lambda r: ql in str(r["sku"]).lower() or ql in str(r["name"]).lower() or ql in str(r.get("category", "")).lower(),
                axis=1,
            )
        ]

    total = len(filtered)
    total_pages = max(1, -(-total // page_size))  # ceiling division
    page_num = min(page_num, total_pages)
    start = (page_num - 1) * page_size
    df_page = filtered.iloc[start : start + page_size]

    st.caption(f"Showing {len(df_page)} items — page {page_num}/{total_pages} — {total} total matching")
    st.dataframe(df_page, use_container_width=True, hide_index=True)

    # Delete product
    if is_admin and not df_page.empty:
        st.markdown('<div class="block-space"></div>', unsafe_allow_html=True)
        del_sku = st.selectbox("Delete product by SKU", options=["-- select --"] + df_page["sku"].tolist())
        if st.button("Delete", type="secondary") and del_sku != "-- select --":
            run_query("DELETE FROM products WHERE sku = ?;", (del_sku,))
            log_audit("delete_product", f"sku={del_sku}")
            st.warning(f"Deleted product SKU {del_sku}")
            st.experimental_rerun()

# -------------------------------
# Page: Sales & Restock
# -------------------------------
elif page == "Sales & Restock":
    st.header("🧾 Sales & Restock")
    products = fetch_df("SELECT product_id, sku, name, sell_price, cost_price, qty FROM products ORDER BY name;")
    if products.empty:
        st.info("No products yet — add some on the Products page.")
    else:
        sku_map = {f"{r['sku']} — {r['name']}": (int(r["product_id"]), float(r["sell_price"]), float(r["cost_price"])) for _, r in products.iterrows()}
        pick = st.selectbox("Select product", options=list(sku_map.keys()))
        pid, sell_price, cost_price = sku_map[pick]

        col1, col2 = st.columns(2)
        with col1:
            ttype = st.selectbox("Transaction Type", options=["sale", "restock", "adjustment"])
        with col2:
            # allow negative numbers only for adjustment (handled below), min_value depends on type
            if ttype == "adjustment":
                qty = st.number_input("Quantity (use negative to subtract)", value=0, step=1)
            else:
                qty = st.number_input("Quantity", value=1, step=1, min_value=1)
        note = st.text_input("Note (optional)")

        # Amount auto-calculation
        if ttype == "sale":
            default_amt = sell_price * qty
            amt = st.number_input(f"Amount ({st.session_state.currency})", value=float(default_amt), step=0.01, format="%.2f")
        elif ttype == "restock":
            default_amt = cost_price * qty
            amt = st.number_input(f"Amount ({st.session_state.currency})", value=float(default_amt), step=0.01, format="%.2f")
        else:
            amt = st.number_input(f"Amount ({st.session_state.currency})", value=0.0, step=0.01, format="%.2f")

        if st.button("Record Transaction", type="primary", disabled=not is_admin):
            if ttype in ("sale", "restock") and qty <= 0:
                st.error("Quantity must be positive for sale/restock.")
            else:
                add_transaction(pid, ttype, int(qty), float(amt), note)
                st.success(f"{ttype.capitalize()} recorded.")
                st.experimental_rerun()

        st.divider()
        st.subheader("Recent Transactions (last 14 days)")
        tx = get_transactions_df(14)
        st.dataframe(tx, use_container_width=True, hide_index=True)

# -------------------------------
# Page: Suppliers
# -------------------------------
elif page == "Suppliers":
    st.header("🤝 Suppliers")
    if not is_admin:
        st.warning("Login as admin to add or edit suppliers.")
    sname = st.text_input("Supplier Name *")
    sphone = st.text_input("Phone")
    semail = st.text_input("Email")
    if st.button("Save Supplier", type="primary", disabled=not is_admin):
        try:
            sid = upsert_supplier(sname.strip(), sphone.strip(), semail.strip())
            st.success(f"Saved supplier (ID: {sid}).")
            st.experimental_rerun()
        except ValueError:
            pass

    sups = fetch_df("SELECT supplier_id, name, phone, email FROM suppliers ORDER BY name;")
    st.subheader("Supplier List")
    st.dataframe(sups, use_container_width=True, hide_index=True)

    if is_admin and not sups.empty:
        del_supplier = st.selectbox("Delete supplier by name", options=["-- select --"] + sups["name"].tolist())
        if st.button("Delete Supplier", type="secondary") and del_supplier != "-- select --":
            run_query("DELETE FROM suppliers WHERE name = ?;", (del_supplier,))
            log_audit("delete_supplier", f"name={del_supplier}")
            st.warning(f"Deleted supplier {del_supplier}")
            st.experimental_rerun()

# -------------------------------
# Page: Transactions
# -------------------------------
elif page == "Transactions":
    st.header("📜 All Transactions")
    tx = get_transactions_df()
    if tx.empty:
        st.info("No transactions yet.")
    else:
        c1, c2, c3 = st.columns(3)
        with c1:
            f_type = st.selectbox("Type filter", options=["All", "sale", "restock", "adjustment"])
        with c2:
            start = st.date_input("Start date", value=datetime.utcnow().date() - timedelta(days=30))
        with c3:
            end = st.date_input("End date", value=datetime.utcnow().date())
        fdf = tx.copy()
        fdf["dt"] = pd.to_datetime(fdf["created_at"])
        tz = pytz.timezone(st.session_state.timezone)
        # Convert filter dates to timezone-aware timestamps for comparison
        start_ts = pd.Timestamp(start).tz_localize(tz)
        end_ts = pd.Timestamp(end).tz_localize(tz) + pd.Timedelta(days=1)
        fdf = fdf[(fdf["dt"] >= start_ts) & (fdf["dt"] < end_ts)]
        if f_type != "All":
            fdf = fdf[fdf["type"] == f_type]
        st.dataframe(fdf.drop(columns=["dt"]), use_container_width=True, hide_index=True)
        csv, fname = to_csv_download(fdf.drop(columns=["dt"]), f"transactions_{start}_to_{end}")
        st.download_button("Download CSV", data=csv, file_name=fname, mime="text/csv")

# -------------------------------
# Page: Stock History
# -------------------------------
elif page == "Stock History":
    st.header("📈 Stock History")
    prods = fetch_df("SELECT sku, product_id, name FROM products ORDER BY name;")
    if prods.empty:
        st.info("No products yet.")
    else:
        sku = st.selectbox("Select product", options=["-- select --"] + prods["sku"].tolist())
        if sku != "-- select --":
            pid = prods[prods["sku"] == sku]["product_id"].iloc[0]
            tx = get_transactions_df(product_id=pid)
            if tx.empty:
                st.info("No transactions for this product.")
            else:
                tx["date"] = pd.to_datetime(tx["created_at"]).dt.date
                tx["stock_change"] = tx.apply(lambda r: -r["quantity"] if r["type"] == "sale" else r["quantity"], axis=1)
                chart = alt.Chart(tx).mark_line(point=True).encode(
                    x="date:T", y="stock_change:Q", color="type:N", tooltip=["date:T", "type:N", "quantity:Q"]
                ).properties(height=300, title=f"Stock Changes for {sku}")
                st.altair_chart(chart, use_container_width=True)
                st.dataframe(tx[["sku", "name", "type", "quantity", "amount", "note", "created_at"]], use_container_width=True, hide_index=True)

# -------------------------------
# Page: Bulk Upload / Export
# -------------------------------
elif page == "Bulk Upload / Export":
    st.header("📥 Bulk Upload / Export")
    st.subheader("Upload Products CSV")
    st.caption("Columns: sku, name, category, supplier, cost_price, sell_price, qty, reorder_level")
    up = st.file_uploader("Choose product CSV", type=["csv"])
    if up and is_admin:
        df = pd.read_csv(up)
        required = {"sku", "name"}
        if not required.issubset(set(df.columns)):
            st.error("CSV must include at least: sku, name.")
        else:
            count = 0
            errors = []
            for i, r in df.fillna("").iterrows():
                try:
                    upsert_product(
                        str(r.get("sku", "")).strip(),
                        str(r.get("name", "")).strip(),
                        str(r.get("category", "")).strip(),
                        str(r.get("supplier", "")).strip(),
                        float(r.get("cost_price", 0) or 0),
                        float(r.get("sell_price", 0) or 0),
                        int(r.get("qty", 0) or 0),
                        int(r.get("reorder_level", 0) or 0),
                    )
                    count += 1
                except Exception as e:
                    errors.append(f"Row {i+2}: {str(e)}")
            st.success(f"Upserted {count} products.")
            if errors:
                st.warning(f"Skipped {len(errors)} rows — download error report.")
                err_csv = pd.DataFrame(errors, columns=["error"]).to_csv(index=False).encode("utf-8")
                st.download_button("Download Error Report", data=err_csv, file_name="product_upload_errors.csv", mime="text/csv")
            st.experimental_rerun()

    st.divider()
    st.subheader("Upload Transactions CSV")
    st.caption("Columns: sku, type (sale/restock/adjustment), quantity, amount (optional), note (optional)")
    up2 = st.file_uploader("Choose transactions CSV", type=["csv"], key="tx_upload")
    if up2 and is_admin:
        df2 = pd.read_csv(up2)
        required2 = {"sku", "type", "quantity"}
        if not required2.issubset(set(df2.columns)):
            st.error("CSV must include: sku, type, quantity.")
        else:
            products = fetch_df("SELECT sku, product_id, qty FROM products;")
            sku_to_pid = dict(zip(products["sku"], products["product_id"]))
            ok, fail = 0, 0
            errors = []
            for i, r in df2.fillna("").iterrows():
                sku = str(r.get("sku", "")).strip()
                pid = sku_to_pid.get(sku)
                ttype = str(r.get("type", "")).strip().lower()
                qty = r.get("quantity", "")
                amt = float(r.get("amount", 0) or 0)
                note = str(r.get("note", ""))
                if not pid:
                    errors.append(f"Row {i+2}: Invalid SKU '{sku}'")
                    fail += 1
                    continue
                if ttype not in {"sale", "restock", "adjustment"}:
                    errors.append(f"Row {i+2}: Invalid type '{ttype}'")
                    fail += 1
                    continue
                try:
                    qty_i = int(qty)
                    if ttype in ("sale", "restock") and qty_i < 1:
                        errors.append(f"Row {i+2}: Quantity must be positive")
                        fail += 1
                        continue
                    add_transaction(pid, ttype, qty_i, amt, note)
                    ok += 1
                except Exception as e:
                    errors.append(f"Row {i+2}: {str(e)}")
                    fail += 1
            st.success(f"Processed {ok} transactions. Skipped {fail}.")
            if errors:
                err_csv = pd.DataFrame(errors, columns=["error"]).to_csv(index=False).encode("utf-8")
                st.download_button("Download Transaction Errors", data=err_csv, file_name="transaction_upload_errors.csv", mime="text/csv")
            st.experimental_rerun()

    st.divider()
    st.subheader("Export Data")
    col1, col2, col3 = st.columns(3)
    with col1:
        prods = fetch_df(
            """
            SELECT p.sku, p.name, p.category, s.name as supplier, p.cost_price, p.sell_price, p.qty, p.reorder_level, p.created_at
            FROM products p LEFT JOIN suppliers s ON p.supplier_id = s.supplier_id
            ORDER BY p.created_at DESC;
            """
        )
        csv, name = to_csv_download(prods, "products_export")
        st.download_button("Download Products CSV", data=csv, file_name=name, mime="text/csv")
    with col2:
        tx = get_transactions_df()
        csv2, name2 = to_csv_download(tx, "transactions_export")
        st.download_button("Download Transactions CSV", data=csv2, file_name=name2, mime="text/csv")
    with col3:
        sups = fetch_df("SELECT supplier_id, name, phone, email FROM suppliers ORDER BY name;")
        csv3, name3 = to_csv_download(sups, "suppliers_export")
        st.download_button("Download Suppliers CSV", data=csv3, file_name=name3, mime="text/csv")

# -------------------------------
# Page: Settings
# -------------------------------
elif page == "Settings":
    st.header("⚙️ Settings & Info")
    st.markdown(
        """
    **App name:** InvyPro  
    **Storage:** SQLite (`inventory.db` by default)  
    **Admin password:** set `INVYPRO_ADMIN` environment variable to require login  
    **Database path:** set `INVYPRO_DB` to change DB location
    """
    )

    st.subheader("Preferences")
    tz_options = ["UTC", "Africa/Accra", "Europe/London", "America/New_York"]
    st.session_state.timezone = st.selectbox("Time Zone", tz_options, index=tz_options.index(st.session_state.timezone) if st.session_state.timezone in tz_options else 0)
    currency_options = ["GH₵", "USD $", "EUR €", "GBP £"]
    st.session_state.currency = st.selectbox("Currency", currency_options, index=currency_options.index(st.session_state.currency) if st.session_state.currency in currency_options else 0)
    st.session_state.prevent_negative_stock = st.checkbox("Prevent negative stock for sales & negative adjustments", value=st.session_state.prevent_negative_stock)

    st.subheader("Demo Data")
    if st.button("Load Sample Data"):
        if not is_admin:
            st.error("Login as admin to load demo data.")
        else:
            # Warning if DB not empty
            existing = fetch_df("SELECT 1 FROM products LIMIT 1;")
            if not existing.empty:
                st.warning("Database already contains products. Loading demo data will update/insert sample SKUs.")
            # insert sample suppliers & products
            upsert_supplier("AquaPlus Ltd", "020-000-0001", "orders@aquaplus.com")
            upsert_supplier("FreshFoods Co", "020-000-0002", "hello@freshfoods.com")
            upsert_product("SKU-001", "Bottled Water 500ml", "Drinks", "AquaPlus Ltd", 1.5, 2.5, 120, 30)
            upsert_product("SKU-002", "Bottled Water 1.5L", "Drinks", "AquaPlus Ltd", 3.0, 5.0, 80, 20)
            upsert_product("SKU-101", "Rice 5kg", "Groceries", "FreshFoods Co", 60.0, 85.0, 40, 10)
            upsert_product("SKU-102", "Rice 25kg", "Groceries", "FreshFoods Co", 260.0, 320.0, 20, 5)
            pid_df = fetch_df("SELECT sku, product_id FROM products;")
            sku2pid = dict(zip(pid_df["sku"], pid_df["product_id"]))
            add_transaction(sku2pid["SKU-001"], "sale", 10, 25.0, "Opening day")
            add_transaction(sku2pid["SKU-001"], "sale", 15, 37.5, "Walk-ins")
            add_transaction(sku2pid["SKU-101"], "restock", 10, 600.0, "Weekly restock")
            add_transaction(sku2pid["SKU-002"], "sale", 5, 25.0, "Quick sale")
            log_audit("load_demo_data", "Sample demo data loaded")
            st.success("Sample data loaded.")
            st.experimental_rerun()

    st.subheader("Danger Zone")
    st.caption("Use with extreme care. Admin only.")
    if st.button("Reset Database (delete all data)"):
        if is_admin:
            run_query("DELETE FROM transactions;")
            run_query("DELETE FROM products;")
            run_query("DELETE FROM suppliers;")
            run_query("DELETE FROM audit_logs;")
            log_audit("reset_database", "All data cleared")
            st.warning("Database cleared.")
            st.experimental_rerun()
        else:
            st.error("Login as admin to reset the database.")
