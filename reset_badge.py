"""One-time reset: re-arm badge capture for product 24 (v1, pg8000).

WHY: the July 15 capture (pre-evidence-verification) persisted
has_bestseller_badge = TRUE with a broken screenshot record. Every check
since sees "badge present, already recorded" -> no new capture will ever
fire while the badge persists. This script:
  1. shows the current state,
  2. deletes the bad July-15 screenshot record(s) for product 24,
  3. resets has_bestseller_badge to FALSE,
so the NEXT hourly check treats the (still live) badge as newly appeared
and captures it under the new verified, full-page, DB-stored pipeline.

RUN ORDER MATTERS: only run this AFTER confirming the latest deploy
(evidence verification + full-page storage) is live — resetting against
the OLD code would just email another bad capture.

HOW (Replit shell): pip install pg8000 (already done previously),
paste DATABASE_PUBLIC_URL below, python3 reset_badge.py, then DELETE
this file (holds credentials).
"""
print("RESET RUNNER v1 (badge re-arm, pg8000).")

import ssl
from urllib.parse import urlparse, unquote
import pg8000.dbapi

DB_URL = "PASTE_DATABASE_PUBLIC_URL_HERE"
PRODUCT_ID = 24

u = urlparse(DB_URL)
params = dict(user=unquote(u.username or ""), password=unquote(u.password or ""),
              host=u.hostname, port=u.port or 5432,
              database=(u.path or "/postgres").lstrip("/"))

def connect():
    try:
        return pg8000.dbapi.connect(**params)
    except Exception:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return pg8000.dbapi.connect(ssl_context=ctx, **params)

conn = connect(); cur = conn.cursor()

print("--- Current state ---")
cur.execute("SELECT id, product_title, has_bestseller_badge, last_checked FROM products WHERE id = %s", (PRODUCT_ID,))
for r in cur.fetchall(): print(" ", r)
cur.execute("SELECT id, LEFT(screenshot_data, 40), achieved_at FROM bestseller_screenshots WHERE product_id = %s", (PRODUCT_ID,))
rows = cur.fetchall()
print(f"  screenshot records: {len(rows)}")
for r in rows: print("   ", r, "<- filename-string = the broken pre-fix record" if rows and not str(r[1]).startswith("iVBOR") else "")

print("--- Purging broken screenshot record(s) (filename strings, not base64 images) ---")
cur.execute("DELETE FROM bestseller_screenshots WHERE product_id = %s AND screenshot_data NOT LIKE 'iVBOR%%'", (PRODUCT_ID,))
print(f"  deleted: {cur.rowcount}")

print("--- Re-arming badge capture ---")
cur.execute("UPDATE products SET has_bestseller_badge = FALSE WHERE id = %s", (PRODUCT_ID,))
print(f"  products updated: {cur.rowcount}")

conn.commit()
print("\n✅ Done. The next hourly check will treat the badge as newly appeared")
print("   and capture a verified full-page screenshot (watch for")
print("   '🏆 New bestseller badge detected!' then '✅ Achievement saved').")
cur.close(); conn.close()
