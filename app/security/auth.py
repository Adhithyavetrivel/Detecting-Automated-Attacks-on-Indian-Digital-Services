"""
Auth primitives: password hashing and JWT creation/verification.

Password hashing uses the `bcrypt` library directly rather than
`passlib`. passlib's last release predates bcrypt 4.x's internal API
changes, and it fails at import/runtime against currently-installed
bcrypt versions — using the actively maintained library directly avoids
that broken compatibility shim entirely. bcrypt still handles per-
password salting automatically, so two users with the same password get
different hashes, defeating precomputed rainbow-table attacks.

JWTs (JSON Web Tokens) are used for stateless auth: the server issues a
signed token at login and doesn't need to keep server-side session state
for every subsequent request — it just verifies the signature.
"""

from datetime import datetime, timedelta, timezone

import bcrypt
from jose import JWTError, jwt

from app.config import get_settings

settings = get_settings()

# bcrypt's algorithm has a hard 72-byte input limit; truncating longer
# passwords is standard practice (what passlib did internally too) so a
# very long passphrase doesn't raise an error instead of just hashing
# the first 72 bytes of it.
_MAX_PASSWORD_BYTES = 72


def hash_password(plain_password: str) -> str:
    truncated = plain_password.encode("utf-8")[:_MAX_PASSWORD_BYTES]
    return bcrypt.hashpw(truncated, bcrypt.gensalt()).decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    truncated = plain_password.encode("utf-8")[:_MAX_PASSWORD_BYTES]
    try:
        return bcrypt.checkpw(truncated, hashed_password.encode("utf-8"))
    except ValueError:
        # Malformed stored hash — treat as a failed verification rather
        # than raising, so a corrupted row can't crash the login endpoint.
        return False


def create_access_token(subject: str, role: str) -> str:
    """
    Create a signed JWT encoding the username (`sub`) and role.

    The role is embedded in the token itself so role checks
    (see app/security/deps.py) don't require a database lookup on every
    request — a deliberate tradeoff of a small staleness window (a
    demoted user keeps old-role access until their token expires) for
    speed and simplicity, which is worth calling out explicitly if asked
    about it in an interview.
    """
    expire = datetime.now(timezone.utc) + timedelta(
        minutes=settings.access_token_expire_minutes
    )
    payload = {"sub": subject, "role": role, "exp": expire}
    return jwt.encode(payload, settings.secret_key, algorithm=settings.algorithm)


def decode_access_token(token: str) -> dict | None:
    """Return the decoded payload, or None if the token is invalid/expired."""
    try:
        return jwt.decode(token, settings.secret_key, algorithms=[settings.algorithm])
    except JWTError:
        return None

