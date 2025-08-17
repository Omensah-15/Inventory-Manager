"""
InvyPro - Professional Inventory Management System
Complete version with all features integrated
"""

import os
import hashlib
import secrets
import sqlite3
import pandas as pd
import streamlit as st
import altair as alt
from datetime import datetime, timedelta
from typing import Optional, Tuple
from contextlib import contextmanager

# ======================
# Configuration
# ======================
st.set_page_config(
    page_title="InvyPro — Inventory Manager",
    page_icon="📦",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Custom CSS
st.markdown("""
<style>
.report-card {border:1px solid #eef2f6;border-radius:10px;padding:12px;margin-bottom:8px;background:#fff;}
.small-label {font-size:0.85rem;color:#6b7280;margin-bottom:0.25rem;}
.big-num {font-size:1.4rem;font-weight:700;margin:0;color:#0f172a;}
.badge {display:inline-block;padding:5px 10px;border-radius:999px;font-size:0.78rem;margin-top:6px;}
.low {background:#fff1f2;color:#861b1b;}
.ok {background:#ecfeff;color:#035b6a;}
.danger {background:#fff7ed;color:#7a3419;padding:6px;border-radius:6px;}
.success {background:#f0fdf4;color:#166534;padding:6px;border-radius:6px;}
.warning {background:#fef9c3;color:#854d0e;padding:6px;border-radius:6px;}
</style>
""", unsafe_allow_html=True)

# ======================
# Database Setup
# ======================
DB_PATH = os.getenv("INVYPRO_DB", "inventory.db")

def get_conn():
    """Return a database connection with proper isolation level."""
    conn = sqlite3.connect(DB_PATH, isolation_level=None)
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.row_factory = sqlite3.Row
    return conn

@contextmanager
def db_session():
    conn = get_conn()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

def init_db():
    """Initialize database with proper schema."""
    with db_session() as conn:
        # Users table
        conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            user_id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            full_name TEXT,
            email TEXT UNIQUE,
            organization TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('admin','manager','staff')),
            is_active BOOLEAN DEFAULT 1,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            last_login TEXT
        );
        """)
        
        # Products table
        conn.execute("""
        CREATE TABLE IF NOT EXISTS products (
            product_id INTEGER PRIMARY KEY AUTOINCREMENT,
            organization TEXT NOT NULL,
            sku TEXT NOT NULL,
            name TEXT NOT NULL,
            category TEXT,
            cost_price REAL DEFAULT 0,
            sell_price REAL DEFAULT 0,
            qty INTEGER DEFAULT 0,
            reorder_level INTEGER DEFAULT 0,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(organization, sku)
        );
        """)
        
        # Transactions table
        conn.execute("""
        CREATE TABLE IF NOT EXISTS transactions (
            txn_id INTEGER PRIMARY KEY AUTOINCREMENT,
            organization TEXT NOT NULL,
            user_id INTEGER NOT NULL,
            product_id INTEGER NOT NULL,
            type TEXT NOT NULL CHECK(type IN ('sale','restock','adjustment')),
            quantity INTEGER NOT NULL,
            amount REAL DEFAULT 0,
            note TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(product_id) REFERENCES products(product_id)
        );
        """)
        
        # Audit logs
        conn.execute("""
        CREATE TABLE IF NOT EXISTS audit_logs (
            log_id INTEGER PRIMARY KEY AUTOINCREMENT,
            organization TEXT NOT NULL,
            user_id INTEGER NOT NULL,
            action TEXT NOT NULL,
            details TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
        """)

# Initialize database
init_db()

# ======================
# Authentication & Security
# ======================
def hash_password(password: str, salt: Optional[str] = None) -> Tuple[str, str]:
    """Hash password with salt using PBKDF2."""
    if salt is None:
        salt = secrets.token_hex(16)
    pw_hash = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt.encode('utf-8'),
        100000
    ).hex()
    return pw_hash, salt

def verify_password(stored_hash: str, stored_salt: str, provided_password: str) -> bool:
    """Verify a password against stored hash."""
    pw_hash, _ = hash_password(provided_password, stored_salt)
    return secrets.compare_digest(pw_hash, stored_hash)

def login_user(username: str, password: str) -> bool:
    """Authenticate user and set session."""
    with db_session() as conn:
        user = conn.execute(
            "SELECT user_id, username, password_hash, salt, organization, role FROM users WHERE username = ? AND is_active = 1",
            (username,)
        ).fetchone()
        
        if user and verify_password(user['password_hash'], user['salt'], password):
            st.session_state.update({
                'authenticated': True,
                'user_id': user['user_id'],
                'username': user['username'],
                'organization': user['organization'],
                'role': user['role'],
                'login_time': datetime.now().isoformat()
            })
            
            # Update last login
            conn.execute(
                "UPDATE users SET last_login = ? WHERE user_id = ?",
                (datetime.now().isoformat(), user['user_id'])
            )
            
            log_audit("login", f"User {username} logged in")
            return True
    return False

def logout_user():
    """Log out current user."""
    if is_authenticated():
        log_audit("logout", f"User {st.session_state.get('username')} logged out")
    st.session_state.clear()
    st.session_state.update({
        'authenticated': False,
        'timezone': 'UTC',
        'currency': 'GH₵',
        'prevent_negative_stock': True
    })

def is_authenticated() -> bool:
    """Check if user is authenticated."""
    return st.session_state.get('authenticated', False)

def get_current_org() -> Optional[str]:
    """Get current organization."""
    return st.session_state.get('organization')

def get_current_user_id() -> Optional[int]:
    """Get current user ID."""
    return st.session_state.get('user_id')

def has_permission(required_role: str) -> bool:
    """Check if user has required permissions."""
    if not is_authenticated():
        return False
    current_role = st.session_state.get('role')
    role_hierarchy = ['staff', 'manager', 'admin']
    return role_hierarchy.index(current_role) >= role_hierarchy.index(required_role)

def log_audit(action: str, details: str = ""):
    """Log an audit event."""
    if not is_authenticated():
        return
        
    with db_session() as conn:
        conn.execute(
            """INSERT INTO audit_logs 
            (organization, user_id, action, details)
            VALUES (?,?,?,?)""",
            (get_current_org(), get_current_user_id(), action, details)
        )

# ======================
# Data Access
# ======================
def fetch_df(query: str, params: Tuple = ()) -> pd.DataFrame:
    """Execute query and return DataFrame."""
    with db_session() as conn:
        return pd.read_sql_query(query, conn, params=params)

def run_query(query: str, params: Tuple = ()):
    """Execute query without returning results."""
    with db_session() as conn:
        conn.execute(query, params)

def get_products(page: int = 1, page_size: int = 50, product_id: Optional[int] = None) -> pd.DataFrame:
    """Get products for current organization."""
    org = get_current_org()
    if not org:
        return pd.DataFrame()
    
    offset = (page - 1) * page_size
    query = """
        SELECT p.*, COALESCE(SUM(CASE WHEN t.type = 'sale' THEN -t.quantity ELSE t.quantity END), 0) as stock_change
        FROM products p
        LEFT JOIN transactions t ON p.product_id = t.product_id
        WHERE p.organization = ?
    """
    params = [org]
    
    if product_id:
        query += " AND p.product_id = ?"
        params.append(product_id)
    
    query += " GROUP BY p.product_id ORDER BY p.created_at DESC"
    
    if not product_id:
        query += " LIMIT ? OFFSET ?"
        params.extend([page_size, offset])
    
    return fetch_df(query, tuple(params))

def add_product(sku: str, name: str, category: str, cost_price: float, 
               sell_price: float, qty: int, reorder_level: int) -> int:
    """Add a new product."""
    org = get_current_org()
    if not org:
        raise ValueError("Not authenticated")
    
    with db_session() as conn:
        try:
            cur = conn.execute(
                """INSERT INTO products 
                (organization, sku, name, category, cost_price, sell_price, qty, reorder_level)
                VALUES (?,?,?,?,?,?,?,?)""",
                (org, sku, name, category, cost_price, sell_price, qty, reorder_level)
            )
            product_id = cur.lastrowid
            log_audit("add_product", f"Added product {sku} (ID: {product_id})")
            return product_id
        except sqlite3.IntegrityError:
            raise ValueError("SKU already exists in this organization")

def add_transaction(product_id: int, ttype: str, quantity: int, amount: float = 0.0, note: str = ""):
    """Record a transaction."""
    org = get_current_org()
    user_id = get_current_user_id()
    if not org or not user_id:
        raise ValueError("Not authenticated")
    
    # Get current stock
    product = fetch_df(
        "SELECT qty, reorder_level FROM products WHERE product_id = ? AND organization = ?",
        (product_id, org)
    )
    if product.empty:
        raise ValueError("Product not found")
    
    current_qty = product.iloc[0]['qty']
    
    # Prevent negative stock if enabled
    if st.session_state.get('prevent_negative_stock', True):
        if ttype == 'sale' and quantity > current_qty:
            raise ValueError(f"Cannot sell {quantity} items, only {current_qty} in stock")
        elif ttype == 'adjustment' and (current_qty + quantity) < 0:
            raise ValueError(f"Adjustment would result in negative stock")
    
    # Update stock
    if ttype == 'sale':
        run_query(
            "UPDATE products SET qty = qty - ? WHERE product_id = ?",
            (quantity, product_id)
        )
    elif ttype in ('restock', 'adjustment'):
        run_query(
            "UPDATE products SET qty = qty + ? WHERE product_id = ?",
            (quantity, product_id)
        )
    
    # Record transaction
    run_query(
        """INSERT INTO transactions 
        (organization, user_id, product_id, type, quantity, amount, note)
        VALUES (?,?,?,?,?,?,?)""",
        (org, user_id, product_id, ttype, quantity, amount, note)
    )
    
    log_audit("add_transaction", 
             f"{ttype} of {quantity} units for product {product_id} (Amount: {amount})")

# ======================
# UI Components
# ======================
def login_form():
    """Render login form."""
    with st.sidebar:
        with st.form("login_form"):
            st.subheader("🔐 Login")
            username = st.text_input("Username")
            password = st.text_input("Password", type="password")
            
            if st.form_submit_button("Login"):
                if login_user(username, password):
                    st.success("Logged in successfully!")
                    st.experimental_rerun()
                else:
                    st.error("Invalid credentials")

def logout_button():
    """Render logout button."""
    if is_authenticated():
        with st.sidebar:
            if st.button("🚪 Logout"):
                logout_user()
                st.experimental_rerun()

def navigation_menu():
    """Render navigation menu based on user role."""
    if not is_authenticated():
        return
    
    menu_items = ["Dashboard", "Products", "Transactions"]
    
    if has_permission('manager'):
        menu_items.extend(["Reports", "Suppliers"])
    
    if has_permission('admin'):
        menu_items.extend(["Users", "Settings"])
    
    with st.sidebar:
        st.selectbox(
            "Navigation",
            menu_items,
            key="page",
            label_visibility="collapsed"
        )

# ======================
# Application Pages
# ======================
def dashboard_page():
    """Dashboard page with KPIs and charts."""
    st.header("📊 Dashboard")
    
    # KPIs
    products = get_products()
    transactions = fetch_df(
        """SELECT * FROM transactions 
        WHERE organization = ? AND created_at >= date('now', '-30 days')""",
        (get_current_org(),)
    )
    
    col1, col2, c3, c4 = st.columns(4)
    with col1:
        st.metric("Total Products", len(products))
    with col2:
        stock_value = (products['qty'] * products['cost_price']).sum()
        st.metric("Stock Value", f"{st.session_state.currency} {stock_value:,.2f}")
    with c3:
        low_stock = len(products[products['qty'] <= products['reorder_level']])
        st.metric("Low Stock Items", low_stock)
    with c4:
        sales_revenue = transactions[transactions['type'] == 'sale']['amount'].sum()
        st.metric("30-Day Sales", f"{st.session_state.currency} {sales_revenue:,.2f}")
    
    # Charts
    st.divider()
    
    # Sales trend chart
    if not transactions.empty:
        sales_data = transactions[transactions['type'] == 'sale'].copy()
        sales_data['date'] = pd.to_datetime(sales_data['created_at']).dt.date
        daily_sales = sales_data.groupby('date')['amount'].sum().reset_index()
        
        chart = alt.Chart(daily_sales).mark_line(point=True).encode(
            x='date:T',
            y=alt.Y('amount:Q', title=f"Revenue ({st.session_state.currency})"),
            tooltip=['date:T', alt.Tooltip('amount:Q', format=",.2f")]
        ).properties(
            title="Sales Trend - Last 30 Days",
            height=300
        )
        st.altair_chart(chart, use_container_width=True)
    
    # Low stock alerts
    st.subheader("🔔 Low Stock Alerts")
    low_stock_items = products[products['qty'] <= products['reorder_level']]
    if not low_stock_items.empty:
        st.dataframe(
            low_stock_items[['sku', 'name', 'qty', 'reorder_level']],
            use_container_width=True,
            hide_index=True
        )
    else:
        st.success("No low stock items")

def products_page():
    """Products management page."""
    st.header("🧾 Products")
    
    # Add product form
    with st.expander("➕ Add New Product", expanded=False):
        with st.form("add_product_form"):
            col1, col2 = st.columns(2)
            with col1:
                sku = st.text_input("SKU *", help="Unique identifier for the product")
                name = st.text_input("Product Name *")
                category = st.text_input("Category")
            with col2:
                cost_price = st.number_input("Cost Price", min_value=0.0, format="%.2f")
                sell_price = st.number_input("Selling Price", min_value=0.0, format="%.2f")
                qty = st.number_input("Initial Quantity", min_value=0, value=0)
            
            reorder_level = st.number_input("Reorder Level", min_value=0, value=10)
            
            if st.form_submit_button("Save Product"):
                try:
                    add_product(sku, name, category, cost_price, sell_price, qty, reorder_level)
                    st.success("Product added successfully!")
                    st.experimental_rerun()
                except ValueError as e:
                    st.error(str(e))
    
    # Product list with search and pagination
    st.subheader("Product Inventory")
    
    search_term = st.text_input("Search products", placeholder="SKU, name or category")
    page_size = st.selectbox("Items per page", [10, 25, 50, 100], index=2)
    page_num = st.number_input("Page", min_value=1, value=1, step=1)
    
    # Get filtered products
    products = get_products(page_num, page_size)
    if search_term:
        search_lower = search_term.lower()
        products = products[
            products.apply(lambda x: 
                search_lower in str(x['sku']).lower() or 
                search_lower in str(x['name']).lower() or 
                search_lower in str(x.get('category', '')).lower(),
                axis=1
            )
        ]
    
    # Display products
    if not products.empty:
        st.dataframe(
            products[['sku', 'name', 'category', 'qty', 'cost_price', 'sell_price']],
            use_container_width=True,
            hide_index=True
        )
        
        # Pagination controls
        total_items = len(get_products(page_size=10000))  # Get total count
        total_pages = max(1, (total_items + page_size - 1) // page_size)
        st.caption(f"Page {page_num} of {total_pages} | Total items: {total_items}")
        
        # Product actions
        with st.expander("Product Actions", expanded=False):
            if has_permission('manager'):
                selected_sku = st.selectbox(
                    "Select product to edit",
                    options=[""] + products['sku'].tolist()
                )
                
                if selected_sku:
                    product = products[products['sku'] == selected_sku].iloc[0]
                    with st.form("edit_product_form"):
                        st.write(f"Editing: {product['name']} ({product['sku']})")
                        
                        new_name = st.text_input("Name", value=product['name'])
                        new_category = st.text_input("Category", value=product['category'])
                        col1, col2 = st.columns(2)
                        with col1:
                            new_cost = st.number_input("Cost Price", value=float(product['cost_price']), format="%.2f")
                            new_qty = st.number_input("Quantity", value=int(product['qty']))
                        with col2:
                            new_sell = st.number_input("Selling Price", value=float(product['sell_price']), format="%.2f")
                            new_reorder = st.number_input("Reorder Level", value=int(product['reorder_level']))
                        
                        if st.form_submit_button("Update Product"):
                            try:
                                run_query(
                                    """UPDATE products SET 
                                    name = ?, category = ?, cost_price = ?, 
                                    sell_price = ?, qty = ?, reorder_level = ?
                                    WHERE product_id = ?""",
                                    (new_name, new_category, new_cost, new_sell, new_qty, new_reorder, product['product_id'])
                                )
                                st.success("Product updated successfully!")
                                log_audit("update_product", f"Updated {product['sku']}")
                                st.experimental_rerun()
                            except Exception as e:
                                st.error(f"Error updating product: {str(e)}")
            
            if has_permission('admin'):
                del_sku = st.selectbox(
                    "Select product to delete",
                    options=[""] + products['sku'].tolist(),
                    key="delete_select"
                )
                if del_sku and st.button("Delete Product", type="secondary"):
                    run_query(
                        "DELETE FROM products WHERE sku = ? AND organization = ?",
                        (del_sku, get_current_org())
                    )
                    st.warning(f"Deleted product: {del_sku}")
                    log_audit("delete_product", f"Deleted {del_sku}")
                    st.experimental_rerun()
    else:
        st.info("No products found. Add your first product above.")

def transactions_page():
    """Transactions management page."""
    st.header("📜 Transactions")
    
    # New transaction form
    with st.expander("➕ Record New Transaction", expanded=False):
        products = get_products()
        if products.empty:
            st.warning("No products available. Please add products first.")
        else:
            product_map = {f"{row['sku']} - {row['name']}": row['product_id'] for _, row in products.iterrows()}
            
            with st.form("new_transaction_form"):
                col1, col2 = st.columns(2)
                with col1:
                    product = st.selectbox("Product", options=list(product_map.keys()))
                    ttype = st.selectbox("Type", ["sale", "restock", "adjustment"])
                with col2:
                    quantity = st.number_input("Quantity", min_value=1, value=1)
                    amount = st.number_input("Amount", min_value=0.0, value=0.0, format="%.2f")
                
                note = st.text_input("Note (optional)")
                
                if st.form_submit_button("Record Transaction"):
                    try:
                        add_transaction(
                            product_map[product],
                            ttype,
                            quantity,
                            amount,
                            note
                        )
                        st.success("Transaction recorded successfully!")
                        st.experimental_rerun()
                    except ValueError as e:
                        st.error(str(e))
    
    # Transaction history
    st.subheader("Transaction History")
    
    # Filters
    col1, col2, col3 = st.columns(3)
    with col1:
        txn_type = st.selectbox("Filter by type", ["All", "sale", "restock", "adjustment"])
    with col2:
        days = st.selectbox("Time period", ["Last 7 days", "Last 30 days", "Last 90 days", "All time"])
    with col3:
        product_filter = st.selectbox(
            "Filter by product", 
            ["All"] + [f"{row['sku']} - {row['name']}" for _, row in products.iterrows()]
        )
    
    # Build query
    query = """
        SELECT t.*, p.sku, p.name as product_name 
        FROM transactions t
        JOIN products p ON t.product_id = p.product_id
        WHERE t.organization = ?
    """
    params = [get_current_org()]
    
    # Apply time filter
    if days != "All time":
        days_num = int(days.split()[1])
        query += " AND t.created_at >= date('now', ?)"
        params.append(f"-{days_num} days")
    
    # Apply type filter
    if txn_type != "All":
        query += " AND t.type = ?"
        params.append(txn_type)
    
    # Apply product filter
    if product_filter != "All":
        sku = product_filter.split(" - ")[0]
        query += " AND p.sku = ?"
        params.append(sku)
    
    query += " ORDER BY t.created_at DESC"
    
    # Show transactions
    transactions = fetch_df(query, tuple(params))
    if not transactions.empty:
        st.dataframe(
            transactions[['created_at', 'type', 'sku', 'product_name', 'quantity', 'amount', 'note']],
            use_container_width=True,
            hide_index=True
        )
        
        # Export button
        csv = transactions.to_csv(index=False).encode('utf-8')
        st.download_button(
            "Export to CSV",
            data=csv,
            file_name=f"transactions_export_{datetime.now().date()}.csv",
            mime='text/csv'
        )
    else:
        st.info("No transactions found for the selected filters")

# ======================
# Main Application Flow
# ======================
def main():
    """Main application flow."""
    # Initialize session state
    if 'authenticated' not in st.session_state:
        st.session_state.authenticated = False
    if 'timezone' not in st.session_state:
        st.session_state.timezone = 'UTC'
    if 'currency' not in st.session_state:
        st.session_state.currency = 'GH₵'
    if 'prevent_negative_stock' not in st.session_state:
        st.session_state.prevent_negative_stock = True
    
    # Show login form if not authenticated
    if not is_authenticated():
        login_form()
        return
    
    # Main application layout for authenticated users
    logout_button()
    navigation_menu()
    
    # Route to the appropriate page
    page = st.session_state.get('page', 'Dashboard')
    if page == 'Dashboard':
        dashboard_page()
    elif page == 'Products':
        products_page()
    elif page == 'Transactions':
        transactions_page()
    elif page == 'Reports' and has_permission('manager'):
        st.header("📊 Reports")
        st.write("Reporting features coming soon!")
    elif page == 'Settings' and has_permission('admin'):
        st.header("⚙️ Settings")
        
        # Organization settings
        with st.expander("Organization Settings"):
            st.text_input("Organization Name", value=st.session_state.organization, disabled=True)
            st.selectbox("Default Currency", ["GH₵", "USD $", "EUR €", "GBP £"], 
                        key="currency")
            st.selectbox("Timezone", ["UTC", "Africa/Accra", "America/New_York", "Europe/London"], 
                        key="timezone")
            st.checkbox("Prevent negative stock", key="prevent_negative_stock")
            
            if st.button("Save Settings"):
                st.success("Settings saved!")
        
        # User management
        with st.expander("User Management"):
            st.write("User management features coming soon!")
    else:
        st.warning("You don't have permission to access this page")

if __name__ == "__main__":
    # Create default admin if no users exist
    with db_session() as conn:
        users_exist = conn.execute("SELECT 1 FROM users LIMIT 1").fetchone()
        if not users_exist:
            pw_hash, salt = hash_password("admin123")
            conn.execute(
                """INSERT INTO users 
                (username, password_hash, salt, organization, role, full_name)
                VALUES (?,?,?,?,?,?)""",
                ("admin", pw_hash, salt, "Default Organization", "admin", "Administrator")
            )
    
    main()
