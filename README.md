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
- `django-cors-headers` for Frontend communication

### Frontend
- React 18+ (with TypeScript)
- Vite (Build tool)
- Tailwind CSS (Styling)
- `@tailwindcss/vite`

### Database
- SQLite (Default for Django development - admin/auth)
- Google BigQuery (For caching transaction data)

## 📋 Prerequisites

- **Python:** Version 3.10 or higher
- **pip:** Python package installer
- **Node.js:** Version 18 or higher
- **npm:** Node package manager
- **Git:** For cloning the repository

### Google Cloud Platform Requirements

- **GCP Account** with a project created
- **BigQuery API** enabled for the project
- **Service Account** with permissions:
  - Read/Write BigQuery Data (`roles/bigquery.dataEditor`)
  - View BigQuery Metadata (`roles/bigquery.metadataViewer`)
  - Run BigQuery Jobs (`roles/bigquery.jobUser`)
- **Service Account Key** downloaded in JSON format

### Google Cloud Blockchain RPC

- Project uses **Google Cloud's public Blockchain RPC service**. [See Google Cloud Docs](https://cloud.google.com/blockchain-rpc/docs)
- **GCP API Key** enabled for the Blockchain RPC API
- **Important:** The application relies on the `debug_traceTransaction` method, which may have limited support on public endpoints

## 🚀 Setup & Installation

### 1. Clone the Repository
```bash
git clone https://github.com/deccs/Ethereum-Transaction-Gas-Auditor.git
cd Ethereum-Transaction-Gas-Auditor
```

### 2. Backend Setup (Django)
```bash
# Navigate to backend directory
cd eth_processor

# Create and activate virtual environment
python -m venv venv
source venv/bin/activate  # On Windows use `venv\Scripts\activate`

# OR with conda
conda create -n gasauditor python=3.11
conda activate gasauditor

# Install dependencies
pip install -r requirements.txt
```

### 3. Frontend Setup (React)
```bash
# Open new terminal or navigate to frontend directory
cd ../bk-app  # Or `cd bk-app` if in project root

# Install Node.js dependencies
npm install
```

### 4. Configuration (.env)
Create a `.env` file in the project root directory with the following structure:

```
# Django Settings
DJANGO_SECRET_KEY="your_strong_random_secret_key_here"
DJANGO_DEBUG="True"  # Set to "False" for production
DJANGO_ALLOWED_HOSTS="127.0.0.1,localhost"

# Google Cloud & BigQuery Settings
PROJECT_ID="your-gcp-project-id"
DATASET_ID="your_bigquery_dataset_id"
TABLE_ID="your_bigquery_table_id"

# Service Account JSON - Choose ONE option:
# Option 1: File path
SERVICE_ACCOUNT_JSON="/path/to/your/service-account-key.json"
# Option 2: JSON content
# SERVICE_ACCOUNT_JSON='{"type": "service_account", "project_id": "...", ...}'

# Google Cloud Blockchain RPC Endpoint
GCP_BLOCKCHAIN_RPC_ENDPOINT="https://blockchain.googleapis.com/v1/projects/YOUR_PROJECT_ID/locations/YOUR_REGION/endpoints/YOUR_NETWORK?key=YOUR_API_KEY"
```

### 5. Build Frontend
```bash
# Make sure you are in the bk-app directory
npm run build
```
This creates an optimized production build in the `bk-app/dist` folder, which Django serves.

### 6. Database Migrations
```bash
# Navigate back to the backend directory
cd ../eth_processor

# Run Django migrations
python manage.py migrate
```

## 🔄 Running the Application

This describes the process to run the application based on the observed working configuration.

1.  **Build the Frontend:**
    *   Navigate to the frontend directory (`bk-app`).
    *   Run the build command:
        ```bash
        npm run build
        ```
    *   This creates the optimized production build files in `bk-app/dist`.

2.  **Start the Django Backend Server:**
    *   Navigate to the backend directory (`eth_processor`).
    *   Ensure your Python virtual environment is activated.
    *   Run the Django development server:
        ```bash
        python manage.py runserver
        ```
    *   This starts the backend API, typically listening on port 8000 (`http://127.0.0.1:8000/`) for API requests defined in your Django `urls.py` (e.g., under `/api/`). Keep this terminal running.

3.  **Access the Application:**
    *   Open your web browser and navigate to: `http://localhost:3000/`
    *   The built React application should load and be functional at this address in this specific project configuration.
    *   Enter a valid Ethereum transaction hash (e.g., `0x...`) and click "Analyze Transaction". The frontend at port 3000 will communicate with the backend API running on port 8000.

*(Note: This configuration, where the built application is accessed on port 3000 while the Django server runs on port 8000, is specific to this project's setup. Ensure any necessary CORS configurations in Django's `settings.py` allow requests from `http://localhost:3000`.)*

## ⚙️ How It Works

1. **User Input:** Transaction hash is entered in the React frontend
2. **API Request:** Frontend sends POST request to Django backend
3. **Transaction Fetching:** Backend retrieves transaction details and receipt
4. **BigQuery Storage:** Data is stored/updated in BigQuery
5. **Trace Analysis:** For confirmed transactions, both trace types are fetched and analyzed
6. **Score Calculation:** Gas efficiency score and suggestions are generated
7. **Response:** JSON data returned to frontend with analysis results
8. **Display:** Frontend renders transaction summary and analysis

## 🔮 Future Improvements

- **Enhanced Analysis:** More sophisticated gas usage heuristics and pattern detection
- **Contract Code Context:** Integration with source code verification services
- **Multi-Chain Support:** Abstract RPC/Chain details for other EVM chains
- **Historical Analytics:** View and compare past analyses
- **Interactive Visualizations:** Charts for gas usage breakdown and call flow
- **Better Error Handling:** More detailed error feedback
- **Containerization:** Docker configuration for easier deployment

## 📄 License
This project is licensed under the MIT License - see the LICENSE file for details.

---

<div align="center">
  
**Made with ❤️ for Ethereum developers**

</div>




