# 📦 InventoryPro — Inventory Management App

**InventoryPro** is a lightweight, professional, and user-friendly **inventory tracking system**. With InvyPro, you can manage products, track sales, restocks, and adjustments, and visualize inventory trends — all directly from your browser.

Try it here: [InvyPro](https://inventory-manager-tiqc6cxbtumh5rd8qh722i.streamlit.app/). 
---

## Features
#### Authentication & Security
- **Secure login system** with PBKDF2 password hashing
- **Organization-based isolation** - Data only visible to your organization's users
- **Account lockout** after multiple failed attempts
- **Session management** with automatic logout
- **Environment-based configuration** for sensitive settings

#### Product Management
- **Add/edit/delete products** with full details (SKU, name, category, etc.)
- **Supplier management** - Link products to suppliers
- **Bulk import/export** via CSV
- **Low stock alerts** with visual indicators
- **Product search** by SKU, name, or category
- **Pagination** for large inventories

#### Sales & Inventory Tracking
- **Record sales** with automatic stock deduction
- **Restock tracking** with automatic inventory updates
- **Stock adjustments** for corrections
- **Negative stock prevention** (configurable)
- **Transaction history** with timestamps
- **Financial reporting** - Cost vs. sell price tracking

#### Reporting & Analytics
- **Dashboard overview** with key metrics:
  - Total SKUs
  - Inventory value
  - Low stock items
  - Sales revenue
- **Visual charts** for sales trends and stock levels
- **Custom date filtering** for transactions
- **Export to CSV** for all data

#### System Features
- **Audit logging** - Every action is recorded
- **Responsive design** - Works on desktop and tablet
- **Dark/light mode** support (follows system preference)
- **Multi-user support** with role-based permissions
- **Localization** for currency and time zones
- **Demo mode** for exploring features without login

#### Settings & Configuration
- **Organization settings** management
- **Currency selection** (supports multiple currencies)
- **Timezone configuration** for proper time tracking
- **Negative stock** prevention toggle
- **Data reset** option for your organization

#### Data Management
- **SQLite database** - Simple single-file storage
- **Automatic backups** (configurable)
- **CSV exports** for all tables
- **Bulk operations** for mass updates
- **Data integrity checks**

#### Mobile-Friendly
- **Responsive UI** adapts to screen size
- **Touch-friendly** controls
- **Optimized performance** for mobile devices
- **Offline-capable** (with some functionality)


---

## Project Structure
Inventory Manager/
- app.py # Main Streamlit app
- requirements.txt # Python dependencies
- README.md # Documentation


---

## Installation

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

## License: *MIT License — free to use and modify.*
---

## 👨‍💻 Author

**Developed by Mensah Obed**
📧 [heavenzlebron7@gmail.com](mailto:heavenzlebron7@gmail.com)

