# 🔍 Ethereum Transaction Gas Auditor

A full-stack web application designed to analyze Ethereum transaction gas usage. This tool fetches transaction details, receipts, and debug traces from Google Cloud Blockchain RPC endpoints, calculates gas efficiency scores, provides optimization suggestions, and caches transaction data in Google BigQuery.

<div align="center">

![Screenshot](https://github.com/user-attachments/assets/c6672cf1-bc7c-4b08-aeeb-5186e6ffc966)

https://github.com/user-attachments/assets/0fa3a17c-c286-4b64-86fa-db26293d79f1

</div>

## ✨ Key Features

- **📊 Transaction Data Fetching:** Retrieves transaction details (`eth_getTransactionByHash`) and receipts (`eth_getTransactionReceipt`)
- **🔬 Debug Trace Analysis:** Fetches detailed execution traces using `debug_traceTransaction` with both:
  - `callTracer` for call flow and gas usage per call
  - `structLog` for step-by-step opcode execution, frequency, and errors
- **📈 Gas Efficiency Scoring:** Calculates a heuristic-based score (0-100) indicating potential gas inefficiencies
- **💡 Optimization Suggestions:** Provides actionable suggestions based on the analysis results
- **💾 BigQuery Caching:** Stores transaction data for faster future retrievals
- **🖥️ Web Interface:** User-friendly React frontend to input transaction hashes and view results
- **🔄 Trace Fallback:** Offers the best available analysis based on available trace types

## 🛠️ Technology Stack

### Backend
- Python 3.10+
- Django 5+
- `requests` for RPC calls
- `google-cloud-bigquery` for BigQuery interaction
- `python-dotenv` for environment variable management
- `django-cors-headers` for Frontend communication (primarily useful if running frontend dev server separately)
- `whitenoise` for serving static files

### Frontend
- React 18+ (with TypeScript)
- Vite (Build tool)
- Tailwind CSS (Styling)
- `axios` (or similar for API calls)

### Database
- SQLite (Default for Django development - admin/auth)
- Google BigQuery (For caching transaction data)

## 📋 Prerequisites

- **Python:** Version 3.10 or higher
- **pip:** Python package installer
- **Node.js:** Version 18 or higher
- **npm:** Node package manager (or yarn/pnpm)
- **Git:** For cloning the repository

### Google Cloud Platform Requirements

- **GCP Account** with a project created
- **BigQuery API** enabled for the project
- **Blockchain Node Engine API** (or similar, depending on the specific RPC endpoint used) enabled for the project
- **Service Account** with permissions:
  - BigQuery Data Editor (`roles/bigquery.dataEditor`)
  - BigQuery Metadata Viewer (`roles/bigquery.metadataViewer`)
  - BigQuery Job User (`roles/bigquery.jobUser`)
- **Service Account Key** downloaded in JSON format (store this securely, **outside** the repository)
- **API Key** (if required by your chosen GCP RPC endpoint)

### Google Cloud Blockchain RPC

- This project uses **Google Cloud's Blockchain Node Engine** or similar RPC service. [See Google Cloud Docs](https://cloud.google.com/blockchain-node-engine/docs)
- **Important:** Ensure your chosen RPC endpoint supports the `debug_traceTransaction` method. Public endpoints might have limitations. Consider using a dedicated node endpoint for full tracing capabilities.

---

## 🚀 Setup & Installation

### 1. Clone the Repository
```bash
git clone https://github.com/deccs/Ethereum-Transaction-Gas-Auditor.git
cd Ethereum-Transaction-Gas-Auditor
```

### 2. Configure Environment Variables
Create a `.env` file in the project root directory (Ethereum-Transaction-Gas-Auditor/) by copying the example below and filling in your actual values. Do NOT commit this file to Git.

```
# .env file content

# Django Settings
DJANGO_SECRET_KEY="your_strong_random_secret_key_here" # Generate a secure random key
DJANGO_DEBUG="True"  # Set to "False" for production
DJANGO_ALLOWED_HOSTS="127.0.0.1,localhost" # Add your domain in production

# Google Cloud & BigQuery Settings
PROJECT_ID="your-gcp-project-id"
DATASET_ID="your_bigquery_dataset_id" # e.g., eth_transactions
TABLE_ID="your_bigquery_table_id"     # e.g., transaction_cache

# Service Account JSON - Choose ONE option (Option 1 Recommended):
# Option 1: Path to the key file (Store the file OUTSIDE the project directory)
SERVICE_ACCOUNT_JSON="/path/to/your/secure/location/service-account-key.json"
# Option 2: JSON content pasted directly (Less manageable, ensure proper quoting/escaping)
# SERVICE_ACCOUNT_JSON='{"type": "service_account", "project_id": "...", ...}'

# Google Cloud Blockchain RPC Endpoint
# Replace with your actual endpoint URL from GCP Blockchain Node Engine or other provider
# Example using Blockchain Node Engine (requires project setup and maybe API Key):
GCP_BLOCKCHAIN_RPC_ENDPOINT="https://YOUR_REGION-eth-mainnet.blockchainnodeengine.googlecloudapis.com/?key=YOUR_API_KEY"
# Or a public endpoint (might have trace limitations):
# GCP_BLOCKCHAIN_RPC_ENDPOINT="https://mainnet.infura.io/v3/YOUR_INFURA_PROJECT_ID"
```

**Security Note:** Store your service-account-key.json file securely outside of your project directory and ensure the .env file is included in your .gitignore.

### 3. Backend Setup (Django)
```bash
# Navigate to the backend directory
cd eth_processor/eth_processor

# Create and activate a Python virtual environment
# Using venv (recommended)
python -m venv venv
source venv/bin/activate  # On Linux/macOS
# venv\Scripts\activate  # On Windows

# Using conda
# conda create -n gasauditor python=3.11
# conda activate gasauditor

# Install Python dependencies
pip install -r ../requirements.txt # requirements.txt is one level up
```

### 4. Frontend Setup (React)
```bash
# Navigate to the frontend directory from the project root
cd ../../bk-app  # Or `cd bk-app` if you are in the project root

# Install Node.js dependencies
npm install
```

### 5. Build Frontend Assets
```bash
# Still in the bk-app directory
npm run build
```

This creates an optimized production build in the bk-app/dist folder. Django will serve these files.

### 6. Initialize Backend Database
```bash
# Navigate back to the backend directory
cd ../eth_processor/eth_processor

# Activate your virtual environment if not already active
# source venv/bin/activate OR venv\Scripts\activate OR conda activate gasauditor

# Apply Django database migrations (for admin panel, auth, etc.)
python manage.py migrate
```

## ▶️ Running the Application

With the setup complete, Django will serve both the backend API and the built React frontend application.

**Ensure Frontend is Built:** You should have already run `npm run build` in the bk-app directory during setup (Step 5). If you make frontend changes, you'll need to run `npm run build` again.

**Start the Django Server:**

1. Navigate to the backend directory (Ethereum-Transaction-Gas-Auditor/eth_processor/eth_processor).

2. Activate your Python virtual environment (e.g., `source venv/bin/activate`).

3. Run the Django development server:
```bash
python manage.py runserver
```

The server will typically start on http://127.0.0.1:8000/. Keep this terminal running.

**Access the Application:**

Open your web browser and navigate to the address shown by the runserver command, usually:
http://127.0.0.1:8000/

Django serves the index.html from your bk-app/dist folder, and Whitenoise serves the associated CSS and JavaScript assets.

The React application should load. Enter a valid Ethereum transaction hash and click "Analyze Transaction". The frontend will make API calls to the backend (e.g., /api/transaction/) on the same host and port.

## ⚙️ How It Works

1. **User Input:** Transaction hash is entered in the React frontend.
2. **API Request:** Frontend sends a POST request to the Django backend API endpoint (e.g., /api/transaction/).
3. **Transaction Fetching:** Backend uses the configured RPC endpoint to retrieve transaction details and receipt.
4. **BigQuery Storage:** Data is formatted and stored/updated in the specified BigQuery table for caching.
5. **Trace Analysis:** If the transaction is confirmed (has a receipt), the backend attempts to fetch debug_traceTransaction data (both callTracer and default/structLog).
6. **Parsing & Scoring:** Traces are parsed, a gas efficiency score is calculated, and optimization suggestions are generated based on heuristics.
7. **Response:** A JSON object containing the fetched data, BigQuery confirmation, trace analysis, score, and suggestions is returned to the frontend.
8. **Display:** Frontend renders the transaction summary, BigQuery status, trace analysis details, score, and suggestions.

## 🔮 Future Improvements

- **Enhanced Analysis:** More sophisticated gas usage heuristics and pattern detection (e.g., identifying expensive loops, storage patterns).
- **Contract Code Context:** Integration with source code verification services (like Etherscan) to link analysis to specific code lines.
- **Multi-Chain Support:** Abstract RPC/Chain details to easily support other EVM-compatible chains.
- **Historical Analytics:** Allow users to view and compare analyses for previously submitted transactions.
- **Interactive Visualizations:** Implement charts for gas usage breakdown per call frame and visual call flow diagrams.
- **Better Error Handling:** Provide more specific user feedback for RPC errors, BigQuery issues, or parsing failures.
- **User Accounts:** Allow users to save their analyses or track specific contracts.
- **Containerization:** Add Docker configuration (Dockerfile, docker-compose.yml) for easier setup and deployment.

## 📄 License
This project is licensed under the MIT License - see the LICENSE file for details.

<div align="center">
Made with ❤️ for Ethereum developers
</div>
