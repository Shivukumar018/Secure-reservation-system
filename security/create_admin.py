# security/create_admin.py
import secrets, pathlib, stat
TOKEN = secrets.token_urlsafe(32)
p = pathlib.Path("admin_token.txt")
p.write_text(TOKEN)
p.chmod(0o600)
print("Wrote admin_token.txt with restrictive perms. Set ADMIN_TOKEN env from this value.")
print(TOKEN)
