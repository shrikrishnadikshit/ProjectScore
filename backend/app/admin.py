"""Command-line admin tasks.

  python -m app.admin create-user --org "Acme Ltd" --email ana@acme.com [--admin] [--name "Ana"]

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
    args = parser.parse_args(argv)

    db.Base.metadata.create_all(db.engine)
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


if __name__ == "__main__":
    sys.exit(main())
