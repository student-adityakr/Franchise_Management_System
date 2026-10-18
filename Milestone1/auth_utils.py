"""Validation, password hashing, JWT, OTP hashing, and email helpers."""
import hashlib
import hmac
import os
import re
import smtplib
import ssl
import unicodedata
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage

import bcrypt
import jwt

# Deliberately follows the milestone's simplified email rule.
EMAIL_PATTERN = re.compile(r"^[A-Za-z0-9._%+-]+@(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}$")


def validate_email(email):
    """Require 2+ letters in the local part, domain name, and final extension."""
    if not email or not EMAIL_PATTERN.fullmatch(email.strip()):
        return False
    local, domain = email.strip().rsplit("@", 1)
    domain_labels = domain.split(".")
    domain_label_before_extension = domain_labels[-2] if len(domain_labels) >= 2 else ""
    local_letters = sum(character.isalpha() for character in local)
    domain_letters = sum(character.isalpha() for character in domain_label_before_extension)
    return local_letters >= 2 and domain_letters >= 2


def password_issues(password):
    """Return a list of password rules that are not satisfied."""
    issues = []
    if len(password) < 8:
        issues.append("At least 8 characters")
    if not re.search(r"[A-Z]", password):
        issues.append("At least one uppercase letter")
    if not re.search(r"[a-z]", password):
        issues.append("At least one lowercase letter")
    if not re.search(r"\d", password):
        issues.append("At least one number")
    if not re.search(r"[^A-Za-z0-9\s]", password):
        issues.append("At least one special symbol")
    return issues


def normalize_answer(answer):
    """Ignore case and surrounding/repeated whitespace in security answers."""
    normalized = unicodedata.normalize("NFKC", answer or "").strip().casefold()
    return " ".join(normalized.split())


def _bcrypt_input(value):
    """Pre-hash to a fixed-length digest so long inputs avoid bcrypt's 72-byte limit."""
    return hashlib.sha256(value.encode("utf-8")).hexdigest().encode("ascii")


def hash_password(password):
    """Hash a password or security answer with SHA-256 pre-hashing plus bcrypt."""
    return bcrypt.hashpw(_bcrypt_input(password), bcrypt.gensalt(rounds=12)).decode("utf-8")


def verify_hash(value, stored_hash):
    """Safely check a value against a bcrypt hash."""
    try:
        return bcrypt.checkpw(_bcrypt_input(value), stored_hash.encode("utf-8"))
    except (ValueError, TypeError):
        return False


def _jwt_secret():
    secret = os.environ.get("JWT_SECRET", "")
    if len(secret) < 32:
        raise RuntimeError("JWT_SECRET is missing or too short. Configure it in Colab Secrets.")
    return secret


def issue_token(subject, role, username, email=None):
    """Create a signed token that expires after two hours."""
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(subject),
        "role": role,
        "username": username,
        "iat": now,
        "exp": now + timedelta(hours=2),
    }
    if email:
        payload["email"] = email
    return jwt.encode(payload, _jwt_secret(), algorithm="HS256")


def decode_token(token):
    """Decode and validate a JWT. Return None for expired/invalid tokens."""
    if not token:
        return None
    try:
        return jwt.decode(token, _jwt_secret(), algorithms=["HS256"])
    except (jwt.PyJWTError, RuntimeError, TypeError, ValueError):
        return None


def hash_otp(email, otp):
    """Create a keyed hash so the six-digit OTP is not stored as plain text."""
    message = f"{email.strip().lower()}:{otp}".encode("utf-8")
    return hmac.new(_jwt_secret().encode("utf-8"), message, hashlib.sha256).hexdigest()


def verify_otp(email, otp, stored_hash):
    if not stored_hash:
        return False
    expected = hash_otp(email, otp)
    return hmac.compare_digest(expected, stored_hash)


def send_otp_email(recipient, otp):
    """Send an OTP using Gmail SMTP SSL and a Gmail App Password."""
    sender = os.environ.get("EMAIL_ADDRESS", "").strip()
    # Gmail displays App Passwords in groups; removing spaces works either way.
    app_password = os.environ.get("EMAIL_PASSWORD", "").replace(" ", "").strip()
    if not sender or not app_password:
        raise RuntimeError("EMAIL_ADDRESS or EMAIL_PASSWORD is missing in Colab Secrets.")

    message = EmailMessage()
    message["Subject"] = "FranchiseOps AI - Password Reset OTP"
    message["From"] = sender
    message["To"] = recipient
    message.set_content(
        f"Your FranchiseOps AI password-reset OTP is: {otp}\n\n"
        "This code expires in 10 minutes. Do not share it with anyone. "
        "If you did not request a password reset, you can ignore this email."
    )

    tls_context = ssl.create_default_context()
    with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=tls_context, timeout=30) as server:
        server.login(sender, app_password)
        server.send_message(message)
