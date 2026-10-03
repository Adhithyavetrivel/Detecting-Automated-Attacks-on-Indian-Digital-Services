"""
Bootstrap script: create the first ADMIN user.

Run once after initial setup, since POST /api/auth/register itself
requires an existing admin token (chicken-and-egg problem this script
solves). Usage:

    python -m scripts.create_admin --username admin --password changeme
"""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.database import SessionLocal, init_db  # noqa: E402
from app.models.user import User, UserRole  # noqa: E402
from app.security.auth import hash_password  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(description="Create the first NetSentinel admin user.")
    parser.add_argument("--username", required=True)
    parser.add_argument("--password", required=True)
    args = parser.parse_args()

    init_db()
    db = SessionLocal()
    try:
        if db.query(User).filter(User.username == args.username).first():
            print(f"User '{args.username}' already exists.")
            return

        user = User(
            username=args.username,
            hashed_password=hash_password(args.password),
            role=UserRole.ADMIN,
        )
        db.add(user)
        db.commit()
        print(f"Admin user '{args.username}' created.")
    finally:
        db.close()


if __name__ == "__main__":
    main()
