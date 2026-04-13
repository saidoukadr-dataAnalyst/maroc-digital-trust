import sys
from pathlib import Path

# Add root project dir to python path if not present
sys.path.append(str(Path(__file__).parent.parent))

from auth_manager import AuthManager
from crypto_engine import CryptoEngine
from pdf_processor import PDFProcessor
from audit_logger import AuditLogger
from blockchain_engine import BlockchainEngine
from ocr_engine import OCREngine
from dlp_engine import DLPEngine
from stamp_engine import StampEngine
from kms_manager import KmsManager

# Global instances (simplified state management for the API)
VAULT_PATH = Path("security_vault")
ARCHIVE_PATH = VAULT_PATH / "archive"

VAULT_PATH.mkdir(exist_ok=True)
ARCHIVE_PATH.mkdir(exist_ok=True)

auth_manager = AuthManager(VAULT_PATH / "users.json")
crypto_engine = CryptoEngine(VAULT_PATH, ARCHIVE_PATH)
pdf_processor = PDFProcessor()
audit_logger = AuditLogger(VAULT_PATH)
blockchain_engine = BlockchainEngine(VAULT_PATH)
ocr_engine = OCREngine()
dlp_engine = DLPEngine()
stamp_engine = StampEngine()
kms_manager = KmsManager(VAULT_PATH)

def get_auth_manager():
    return auth_manager

def get_crypto_engine():
    return crypto_engine

def get_pdf_processor():
    return pdf_processor

def get_blockchain_engine():
    return blockchain_engine

def get_ocr_engine():
    return ocr_engine

def get_dlp_engine():
    return dlp_engine

def get_stamp_engine():
    return stamp_engine

def get_audit_logger():
    return audit_logger

def get_kms_manager():
    return kms_manager
