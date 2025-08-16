# inventory_app.py
import streamlit as st
import pandas as pd
import os

st.set_page_config(page_title="📦 Inventory Tracker", layout="centered")

# --- Load or create data ---
DATA_FILE = "inventory.csv"
LOW_STOCK_LIMIT = 5  # Threshold for low stock alert

if os.path.exists(DATA_FILE):
    df = pd.read_csv(DATA_FILE)
else:
    df = pd.DataFrame(columns=["Product", "Stock", "Price"])

# --- App title ---
st.title("📦 Inventory Tracker")

# --- Add new product ---
st.subheader("➕ Add New Product")
with st.form("add_form", clear_on_submit=True):
    name = st.text_input("Product Name")
    stock = st.number_input("Stock", min_value=0, step=1)
    price = st.number_input("Price", min_value=0.0, step=0.01)
    add_btn = st.form_submit_button("Add Product")

if add_btn and name:
    if name in df["Product"].values:
        st.warning("Product already exists. Please update stock instead.")
    else:
        new_row = {"Product": name, "Stock": stock, "Price": price}
        df = pd.concat([df, pd.DataFrame([new_row])], ignore_index=True)
        df.to_csv(DATA_FILE, index=False)
        st.success(f"Added '{name}' to inventory.")

# --- Update stock ---
st.subheader("✏️ Update Stock")
with st.form("update_form"):
    product_list = df["Product"].tolist()
    if product_list:
        product = st.selectbox("Select Product", product_list)
        change = st.number_input("Change in Stock (+/-)", step=1)
        update_btn = st.form_submit_button("Update Stock")
        if update_btn:
            df.loc[df["Product"] == product, "Stock"] += change
            df.to_csv(DATA_FILE, index=False)
            st.success(f"Updated stock for '{product}'.")
    else:
        st.info("No products in inventory yet.")

# --- Low stock alerts ---
if not df.empty:
    low_stock_items = df[df["Stock"] <= LOW_STOCK_LIMIT]
    if not low_stock_items.empty:
        st.warning("⚠️ Low Stock Alert!")
        st.table(low_stock_items)

# --- View inventory ---
st.subheader("📋 Current Inventory")
st.dataframe(df)

# --- Stock chart ---
if not df.empty:
    st.subheader("📊 Stock Levels")
    st.bar_chart(df.set_index("Product")["Stock"])

# --- Download CSV ---
if not df.empty:
    csv = df.to_csv(index=False).encode("utf-8")
    st.download_button(
        "⬇️ Download CSV",
        csv,
        "inventory.csv",
        "text/csv",
        key="download_csv"
    )
