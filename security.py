"""دوال الأمان: تجزئة كلمات المرور (PBKDF2-HMAC-SHA256) والتحقق منها."""
import hashlib
import hmac
import re
import secrets

DEFAULT_ITERATIONS = 100_000
ALGORITHM = "pbkdf2_sha256"


def hash_password(password: str, iterations: int = DEFAULT_ITERATIONS) -> str:
    """يعيد نصًا بالشكل: algorithm$iterations$salt$hash (كله hex)."""
    if not password:
        raise ValueError("كلمة المرور فارغة")
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return f"{ALGORITHM}${iterations}${salt.hex()}${dk.hex()}"


def verify_password(stored: str, password: str) -> bool:
    try:
        algo, iterations, salt_hex, hash_hex = stored.split("$")
        if algo != ALGORITHM:
            return False
        dk = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), bytes.fromhex(salt_hex), int(iterations)
        )
    except (ValueError, AttributeError):
        return False
    return hmac.compare_digest(dk.hex(), hash_hex)


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def check_password_strength(password: str) -> list:
    """يعيد قائمة بالأخطاء (فارغة إذا كانت كلمة المرور مقبولة)."""
    errors = []
    if len(password) < 8:
        errors.append("كلمة المرور يجب ألا تقل عن 8 أحرف.")
    if not re.search(r"[A-Za-z]", password):
        errors.append("كلمة المرور يجب أن تحتوي على حرف واحد على الأقل.")
    if not re.search(r"\d", password):
        errors.append("كلمة المرور يجب أن تحتوي على رقم واحد على الأقل.")
    return errors
