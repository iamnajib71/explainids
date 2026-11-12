"""Print a console account entry for EXPLAINIDS_USERS: python scripts/hash_password.py <name>

The password is read without echo and never written anywhere; paste the printed `name:hash` into the deployment's
secret settings (several accounts: join entries with commas).
"""
import getpass
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from ids.auth import hash_password  # noqa: E402

if __name__ == "__main__":
    if len(sys.argv) != 2 or ":" in sys.argv[1] or "," in sys.argv[1]:
        sys.exit("usage: python scripts/hash_password.py <name>   (no ':' or ',' in the name)")
    password = getpass.getpass("Password (12+ characters): ")
    if len(password) < 12 or password != getpass.getpass("Again: "):
        sys.exit("passwords differ or are shorter than 12 characters")
    print(f"{sys.argv[1]}:{hash_password(password)}")
