"""Cleanup runner v2 (pg8000 edition) — replaces the psycopg2 version,
whose compiled extension is broken in Replit's environment.

HOW TO RUN (Replit shell):
  1. pip install pg8000
  2. Railway -> Postgres service -> Variables -> copy DATABASE_PUBLIC_URL
  3. Paste it into DB_URL below
  4. python3 cleanup_run.py
  5. Delete this file afterward (it briefly holds DB credentials); never commit it.

Safety: one transaction; commits ONLY if the built-in verification passes
(orphan counts all zero). Any error or nonzero count -> automatic rollback,
database untouched.
"""
print("CLEANUP RUNNER v2 (pg8000). If this line is missing, you have the old psycopg2 version.")

import ssl
from urllib.parse import urlparse, unquote
import pg8000.dbapi

DB_URL = "postgresql://postgres:QYBcSBiasXDjOTfcVxBSNGVZaWDljGnl@trolley.proxy.rlwy.net:53698/railway"

DOOMED = "josh.matern+test1@gmail.com"   # the FK-blocked account

u = urlparse(DB_URL)
params = dict(
    user=unquote(u.username or ""), password=unquote(u.password or ""),
    host=u.hostname, port=u.port or 5432, database=(u.path or "/postgres").lstrip("/"),
)

def connect():
    try:
        return pg8000.dbapi.connect(**params)          # plain first
    except Exception:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE                 # Railway certs may be self-signed
        return pg8000.dbapi.connect(ssl_context=ctx, **params)

CLEANUP = [
    ("rankings",              "DELETE FROM rankings WHERE product_id IN (SELECT id FROM products WHERE user_id IN (SELECT id FROM users WHERE LOWER(email)=%s))"),
    ("baseline_screenshots",  "DELETE FROM baseline_screenshots WHERE product_id IN (SELECT id FROM products WHERE user_id IN (SELECT id FROM users WHERE LOWER(email)=%s))"),
    ("bestseller_screenshots","DELETE FROM bestseller_screenshots WHERE product_id IN (SELECT id FROM products WHERE user_id IN (SELECT id FROM users WHERE LOWER(email)=%s))"),
    ("target_categories",     "DELETE FROM target_categories WHERE product_id IN (SELECT id FROM products WHERE user_id IN (SELECT id FROM users WHERE LOWER(email)=%s))"),
    ("products",              "DELETE FROM products WHERE user_id IN (SELECT id FROM users WHERE LOWER(email)=%s)"),
    ("api_usage",             "DELETE FROM api_usage WHERE user_id IN (SELECT id FROM users WHERE LOWER(email)=%s)"),
    ("users",                 "DELETE FROM users WHERE LOWER(email)=%s"),
]

conn = connect()
cur = conn.cursor()

print(f"--- Deleting {DOOMED} and all its data (single transaction) ---")
for label, sql in CLEANUP:
    cur.execute(sql, (DOOMED,))
    print(f"  {label}: {cur.rowcount} row(s) deleted")

print("\n--- Verification: remaining users ---")
cur.execute("SELECT id, email, subscription_status FROM users ORDER BY id")
for row in cur.fetchall():
    print(" ", row)

print("\n--- Verification: orphan counts (expect all zeros) ---")
cur.execute("""
    SELECT
      (SELECT COUNT(*) FROM products p LEFT JOIN users u ON p.user_id = u.id WHERE u.id IS NULL),
      (SELECT COUNT(*) FROM rankings r LEFT JOIN products p ON r.product_id = p.id WHERE p.id IS NULL),
      (SELECT COUNT(*) FROM baseline_screenshots b LEFT JOIN products p ON b.product_id = p.id WHERE p.id IS NULL),
      (SELECT COUNT(*) FROM bestseller_screenshots s LEFT JOIN products p ON s.product_id = p.id WHERE p.id IS NULL),
      (SELECT COUNT(*) FROM target_categories t LEFT JOIN products p ON t.product_id = p.id WHERE p.id IS NULL)
""")
op, orr, ob, os_, ot = cur.fetchone()
print(f"  orphan products={op}, rankings={orr}, baselines={ob}, screenshots={os_}, targets={ot}")

if any([op, orr, ob, os_, ot]):
    print("\n⚠️ Orphans found — rolling back; NOTHING was changed. Report these numbers back.")
    conn.rollback()
else:
    conn.commit()
    print("\n✅ All clean — committed.")

cur.close(); conn.close()
