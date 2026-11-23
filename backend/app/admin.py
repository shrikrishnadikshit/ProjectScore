"""Command-line admin tasks.

  python -m app.admin create-user --org "Acme Ltd" --email ana@acme.com [--admin] [--name "Ana"]
  python -m app.admin list-users
  python -m app.admin reset-password --email ana@acme.com [--clear-mfa]

The password is asked for interactively (or read from the PASSWORD environment variable).
"""

import argparse
import getpass
import os
import sys

from . import db
from .auth import create_user


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m app.admin")
    sub = parser.add_subparsers(dest="command", required=True)
    cu = sub.add_parser("create-user", help="create a user (and the organisation if new)")
    cu.add_argument("--org", required=True)
    cu.add_argument("--email", required=True)
    cu.add_argument("--name")
    cu.add_argument("--admin", action="store_true")
    sub.add_parser("list-users", help="show every user's email, role and organisation (no passwords)")
    rp = sub.add_parser("reset-password", help="set a new password for a user and sign them out everywhere")
    rp.add_argument("--email", required=True)
    rp.add_argument("--clear-mfa", action="store_true", help="also turn off two-step login (lost phone)")
    args = parser.parse_args(argv)

    db.Base.metadata.create_all(db.engine)
    if args.command == "list-users":
        return _list_users()
    if args.command == "reset-password":
        return _reset(args.email, args.clear_mfa)
    password = os.getenv("PASSWORD") or getpass.getpass("Password (12+ characters): ")
    session = db.SessionLocal()
    try:
        user = create_user(session, args.org, args.email, password, "admin" if args.admin else "member", args.name)
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    finally:
        session.close()
    print(f"Created {user.role} {user.email} in organisation '{args.org}'")
    return 0


def _list_users() -> int:
    from sqlalchemy import select

    from .models import User, UserMfa

    session = db.SessionLocal()
    try:
        users = session.scalars(select(User).order_by(User.id)).all()
        if not users:
            print("No users yet. The first owner is created on start-up from ADMIN_EMAIL and ADMIN_PASSWORD.")
        for u in users:
            mfa = session.get(UserMfa, u.id)
            print(f"{u.email:40} {u.role:7} {'active' if u.active else 'DISABLED':9} "
                  f"{'2-step on' if mfa and mfa.enabled else '':10} {u.org.name if u.org else ''}")
    finally:
        session.close()
    return 0


def _reset(email: str, clear_mfa: bool) -> int:
    from sqlalchemy import select

    from . import auth
    from .models import User, UserMfa

    session = db.SessionLocal()
    try:
        user = session.scalars(select(User).where(User.email == email.strip().lower())).first()
        if user is None:
            print(f"Error: no user with email {email}. Run 'python -m app.admin list-users' to see them.", file=sys.stderr)
            return 1
        password = os.getenv("PASSWORD") or getpass.getpass("New password (12+ characters): ")
        if len(password) < auth.MIN_PASSWORD_LENGTH:
            print(f"Error: the password must be at least {auth.MIN_PASSWORD_LENGTH} characters", file=sys.stderr)
            return 1
        auth.set_password(session, user, password)
        auth.end_all_sessions(session, user)
        if not user.active:
            user.active = True
        if clear_mfa and (row := session.get(UserMfa, user.id)):
            session.delete(row)
        session.commit()
        from .audit import record

        record(session, user, "password_reset", "command line" + (", two-step login cleared" if clear_mfa else ""))
    finally:
        session.close()
    print(f"New password set for {email}. Sign in at the website now.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
