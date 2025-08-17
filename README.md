# 📦 InventoryPro — Inventory Management App

**InventoryPro** is a lightweight, professional, and user-friendly **inventory tracking system**.
Try it here: [InvyPro](https://inventory-manager-tiqc6cxbtumh5rd8qh722i.streamlit.app/).  
With InvyPro, you can manage products, track sales, restocks, and adjustments, and visualize inventory trends — all directly from your browser.

---

## Features
- **Secure login** with environment-based password.
- **Product management**: Add, edit, delete products.
- **Sales & restock tracking** with automatic stock updates.
- **Stock adjustments** with negative stock prevention.
- **Search & filtering** for quick access to items.
- **Audit logs** for every action performed.
- **Data export** to CSV for reporting.
- **Responsive design** — works on desktop and tablet.

---

## 📂 Project Structure
Inventory Manager/
- app.py # Main Streamlit app
- requirements.txt # Python dependencies
- README.md # Documentation


---

## ⚙️ Installation

### 1. Clone the repository
```
git clone https://github.com/Omeansah-15/InventoryPro.git
cd InventoryPro
```
---
### 2. Create a virtual environment (optional but recommended)
```bash
python -m venv venv
source venv/bin/activate      # Mac/Linux
venv\Scripts\activate         # Windows
```
---
### 3. Install dependencies
```bash
pip install -r requirements.txt
```
---
## Environment Variables
Create a .env file in the project root or set them in your terminal:
```
# macOS/Linux
export INVYPRO_ADMIN="yourpassword"
export INVYPRO_DB="/absolute/path/to/inventory.db"

# Windows PowerShell
$env:INVYPRO_ADMIN="yourpassword"
$env:INVYPRO_DB="C:\full\path\inventory.db"
```
---
## Run the App
```
streamlit run app.py
```

## 📜 License

**MIT License — free to use and modify.**
---

## 👨‍💻 Author

**Developed by Mensah Obed**
📧 [heavenzlebron7@gmail.com](mailto:heavenzlebron7@gmail.com)

