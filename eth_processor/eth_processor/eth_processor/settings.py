# eth_processor/settings.py

import os
from pathlib import Path
from dotenv import load_dotenv

# BASE_DIR points to the directory containing manage.py:
# /c/.../Ethereum-Transaction-Gas-Auditor/eth_processor/eth_processor
BASE_DIR = Path(__file__).resolve().parent.parent

# --- Load Environment Variables ---
# Go up TWO levels from BASE_DIR to find the .env file in the main project root
# /c/.../Ethereum-Transaction-Gas-Auditor/.env
dotenv_path = BASE_DIR.parent.parent / ".env"
load_dotenv(dotenv_path=dotenv_path)
print(f"Attempting to load .env from: {dotenv_path}")  # Debug print
if not os.path.exists(dotenv_path):
    print(f"!!! WARNING: .env file not found at calculated path: {dotenv_path}")

# --- Security Settings ---
SECRET_KEY = os.environ.get(
    "DJANGO_SECRET_KEY", "django-insecure-fallback-key-for-development-only"
)
DEBUG = os.environ.get("DJANGO_DEBUG", "True").lower() in ("true", "1", "t")

ALLOWED_HOSTS = [
    host.strip()
    for host in os.environ.get("DJANGO_ALLOWED_HOSTS", "").split(",")
    if host.strip()
]
if DEBUG and not ALLOWED_HOSTS:
    ALLOWED_HOSTS = ["127.0.0.1", "localhost"]
# Add any production hosts via the environment variable DJANGO_ALLOWED_HOSTS

print(f"DEBUG setting: {DEBUG}")
print(f"ALLOWED_HOSTS: {ALLOWED_HOSTS}")

# --- Application definition ---
INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",  # Needed for static file handling
    # Your custom apps
    "transactions",
    # Third-party apps
    "corsheaders",
    # Whitenoise is added via middleware
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    # Whitenoise middleware - Serves static files efficiently
    "whitenoise.middleware.WhiteNoiseMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "corsheaders.middleware.CorsMiddleware",  # Place CORS after sessions/before common if issues arise
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

# --- CORS Configuration ---
CORS_ALLOWED_ORIGINS = [
    "http://localhost:3000",  # Example: Vite dev server
    "http://127.0.0.1:3000",
    "http://localhost:5173",  # Another common Vite port
    "http://127.0.0.1:5173",
    # Add your deployed frontend URL here
    # e.g., "https://your-auditor-app.com"
]
# If you need to allow credentials (cookies, auth headers) from frontend
# CORS_ALLOW_CREDENTIALS = True
# Consider restricting further in production if possible

ROOT_URLCONF = "eth_processor.urls"  # Points to the inner eth_processor/urls.py

# --- Frontend Build Paths (Relative to BASE_DIR) ---
# Assumes 'bk-app' frontend folder is SIBLING to the 'eth_processor' Django app root folder
# Adjust if your frontend ('bk-app') lives elsewhere relative to BASE_DIR
FRONTEND_DIR = BASE_DIR.parent.parent / "bk-app"
FRONTEND_DIST_DIR = FRONTEND_DIR / "dist"
FRONTEND_ASSETS_DIR = FRONTEND_DIST_DIR / "assets"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        # Look for index.html in the frontend's build output directory
        "DIRS": [FRONTEND_DIST_DIR],
        "APP_DIRS": True,  # Allows finding templates in apps (like admin)
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = (
    "eth_processor.wsgi.application"  # Points to inner eth_processor/wsgi.py
)

# --- Database ---
# Place db.sqlite3 inside BASE_DIR (the directory with manage.py)
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": BASE_DIR / "db.sqlite3",  # Use BASE_DIR Path object directly
    }
}

# --- Password validation ---
AUTH_PASSWORD_VALIDATORS = [
    {
        "NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"
    },
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator"},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

# --- Internationalization ---
LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True

# --- Static files (CSS, JavaScript, Images) ---
# URL prefix for static files (e.g., /assets/main.js) - Should match frontend requests
STATIC_URL = "/assets/"

# Where Django looks for static files NOT associated with an app during development
# Point this to the frontend's built assets folder
STATICFILES_DIRS = [
    FRONTEND_ASSETS_DIR,
]

# Where `collectstatic` will gather ALL static files for deployment.
# Whitenoise serves from here when DEBUG=False.
# Place it outside the Django project root, e.g., sibling to 'eth_processor'
STATIC_ROOT = BASE_DIR.parent.parent / "staticfiles_collected"

# Whitenoise storage backend (Recommended for production)
# Compresses files and adds unique hashes to filenames for caching
# Enable this when DEBUG = False
if not DEBUG:
    STATICFILES_STORAGE = "whitenoise.storage.CompressedManifestStaticFilesStorage"
# Note: When DEBUG=True, Whitenoise middleware serves directly from STATICFILES_DIRS


# --- Debug prints for paths ---
print("-" * 20 + " Path Check " + "-" * 20)
print(f"BASE_DIR: {BASE_DIR}")
print(f"FRONTEND_DIST_DIR: {FRONTEND_DIST_DIR}")
print(f"FRONTEND_ASSETS_DIR (for STATICFILES_DIRS): {FRONTEND_ASSETS_DIR}")
print(f"STATIC_ROOT (for collectstatic): {STATIC_ROOT}")
print(f"Database Path: {DATABASES['default']['NAME']}")
print(f"Does FRONTEND_DIST_DIR exist? {os.path.exists(FRONTEND_DIST_DIR)}")
print(f"Does FRONTEND_ASSETS_DIR exist? {os.path.exists(FRONTEND_ASSETS_DIR)}")
if os.path.exists(FRONTEND_ASSETS_DIR):
    try:
        print(f"Contents of FRONTEND_ASSETS_DIR: {os.listdir(FRONTEND_ASSETS_DIR)}")
    except Exception as e:
        print(f"Error listing FRONTEND_ASSETS_DIR contents: {e}")
print("-" * 20 + " End Path Check " + "-" * 20)

# --- Default primary key field type ---
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# --- BigQuery & RPC Settings (Loaded from .env) ---
PROJECT_ID = os.environ.get("PROJECT_ID")
DATASET_ID = os.environ.get("DATASET_ID")
TABLE_ID = os.environ.get("TABLE_ID")
SERVICE_ACCOUNT_JSON = os.environ.get("SERVICE_ACCOUNT_JSON")  # Path or JSON string
GCP_BLOCKCHAIN_RPC_ENDPOINT = os.environ.get("GCP_BLOCKCHAIN_RPC_ENDPOINT")

# --- Environment Variable Check ---
print("-" * 20 + " Env Var Check " + "-" * 20)
print(f"PROJECT_ID: {'Loaded' if PROJECT_ID else '*** MISSING ***'}")
print(f"DATASET_ID: {'Loaded' if DATASET_ID else '*** MISSING ***'}")
print(f"TABLE_ID: {'Loaded' if TABLE_ID else '*** MISSING ***'}")
print(
    f"SERVICE_ACCOUNT_JSON: {'Loaded' if SERVICE_ACCOUNT_JSON else '*** MISSING ***'}"
)
print(
    f"GCP_BLOCKCHAIN_RPC_ENDPOINT: {'Loaded' if GCP_BLOCKCHAIN_RPC_ENDPOINT else '*** MISSING ***'}"
)
required_vars_present = all(
    [
        PROJECT_ID,
        DATASET_ID,
        TABLE_ID,
        SERVICE_ACCOUNT_JSON,
        GCP_BLOCKCHAIN_RPC_ENDPOINT,
    ]
)
if not required_vars_present:
    print(
        "!!! WARNING: One or more required environment variables are missing! Check .env file. !!!"
    )
    print(f".env path checked: {dotenv_path}")
print("-" * 20 + " End Env Var Check " + "-" * 20)

# --- Optional Logging Configuration ---
# LOGGING = { ... } # Define complex logging if needed
