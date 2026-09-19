"""Export every captured badge screenshot from the Railway Postgres DB to PNG files.

Usage (from your laptop, with the Railway DATABASE_URL in your shell):

    pip install psycopg2-binary
    DATABASE_URL='postgresql://...' python export_screenshots.py

Or from the repo folder on Railway:  railway run python export_screenshots.py

Writes ./captures/<screenshot_id>_<product_id>_<achieved_at>.png plus captures/index.csv
(id, product title, category/achievement, rank, timestamp) so you can pick which ones
to blur and use on the blog.
"""
import base64, csv, os, re
import psycopg2

url = os.environ["DATABASE_URL"]
conn = psycopg2.connect(url)
cur = conn.cursor()
cur.execute("""
    SELECT s.id, s.product_id, p.product_title, s.category, s.rank_achieved,
           s.achieved_at, s.screenshot_data
    FROM bestseller_screenshots s
    JOIN products p ON p.id = s.product_id
    ORDER BY s.achieved_at
""")

os.makedirs("captures", exist_ok=True)
with open("captures/index.csv", "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["screenshot_id", "product_id", "title", "category_and_reason", "rank", "achieved_at", "file"])
    for sid, pid, title, cat, rank, at, data in cur.fetchall():
        if not data:
            continue
        if isinstance(data, str):
            if data.startswith("data:image"):
                data = data.split(",", 1)[1]
            raw = base64.b64decode(data)
        else:
            raw = bytes(data)
        stamp = re.sub(r"[^0-9T]", "", at.isoformat())[:15]
        name = f"captures/{sid}_{pid}_{stamp}.png"
        with open(name, "wb") as img:
            img.write(raw)
        w.writerow([sid, pid, title, cat, rank, at, name])
        print("wrote", name, "-", (title or "")[:50], "-", cat)

print("done; see captures/index.csv")
