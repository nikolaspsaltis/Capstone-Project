#!/usr/bin/env python3
import os
import sys
from pathlib import Path

from sqlalchemy import select

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def _load_app_modules():
    if str(PROJECT_ROOT) not in sys.path:
        sys.path.insert(0, str(PROJECT_ROOT))
    from app.auth import hash_password
    from app.database import SessionLocal
    from app.models import User

    return hash_password, SessionLocal, User


def main() -> int:
    hash_password, SessionLocal, User = _load_app_modules()

    username = os.getenv("ADMIN_USERNAME", "").strip()
    password = os.getenv("ADMIN_PASSWORD", "")

    if not username or not password:
        print("ERROR: ADMIN_USERNAME and ADMIN_PASSWORD must be set.")
        print("Example:")
        print("  export ADMIN_USERNAME=admin")
        print("  export ADMIN_PASSWORD='strong-admin-password'")
        return 1

    if len(password.encode("utf-8")) > 72:
        print("ERROR: ADMIN_PASSWORD is too long for bcrypt (max 72 bytes).")
        return 1

    db = SessionLocal()
    try:
        user = db.execute(select(User).where(User.username == username)).scalars().first()
        if user is None:
            user = User(
                username=username,
                password_hash=hash_password(password),
                role="admin",
            )
            db.add(user)
            action = "created"
        else:
            user.password_hash = hash_password(password)
            user.role = "admin"
            action = "updated"

        db.commit()
    finally:
        db.close()

    print(f"Admin user {action}: username='{username}' role='admin'")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
