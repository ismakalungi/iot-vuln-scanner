import os
from pathlib import Path
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(os.path.join(BASE_DIR, '.env'))

DATABASE_PATH = os.getenv('DATABASE_PATH', os.path.join(BASE_DIR, 'dashboard', 'db.sqlite'))
SECRET_KEY = os.getenv('SECRET_KEY', 'dev-secret-key-change-me')
ADMIN_USERNAME = os.getenv('ADMIN_USERNAME', 'admin')
ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD', 'admin')