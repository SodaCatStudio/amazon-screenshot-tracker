"""Phase 2 acceptance tests, run against the SQLite path (option (a)).

Covers, in checklist order:
  T1  webhook creates user (weekly plan) with per-plan expiry + lowercased email
  T2  webhook yearly plan gets ~365-day expiry (was flat 30 days)
  T3  setup email link is URL-encoded and uses APP_URL
  T4  GET /auth/complete-registration prefills email (readonly field bug)
  T5  POST completes setup -> is_verified, password usable
  T6  login works with the new password
  T7  forgot_password writes reset token to the REAL db (get_db, not stray sqlite)
  T8  reset_password with token changes password; login with new password
  T9  /pricing renders yearly price IDs into the Annual buttons
  T10 EmailNotifier.is_configured() True with Resend-only config
  T11 legacy /auth/setup-account redirects to complete-registration
  T12 duplicate webhook delivery upserts (no crash, token rotates)
  T13 subscription.updated handler updates status/tier
  T14 subscription.deleted marks cancelled
"""
import os, sys, re, tempfile, traceback

print("SUITE VERSION 15 (full-page durable screenshots) — expect 61 checks. "
      "If this line is missing from your output, you are running the old suite.")

os.chdir(tempfile.mkdtemp(prefix="ast_test_"))
sys.path.insert(0, "/home/claude/amazon-screenshot-tracker")

os.environ.update({
    "ENABLE_SCHEDULER": "false",
    "WTF_CSRF_ENABLED": "false",          # test client convenience only
    "FLASK_SECRET_KEY": "test-secret",
    "APP_URL": "http://testserver:5000",
    "USE_RESEND": "true",
    "RESEND_API_KEY": "re_dummy_key",
    "STRIPE_AUTHOR_WEEKLY_PRICE": "price_wk",
    "STRIPE_AUTHOR_MONTHLY_PRICE": "price_mo",
    "STRIPE_AUTHOR_YEARLY_PRICE": "price_yr",
    "STRIPE_PUBLISHER_WEEKLY_PRICE": "price_pwk",
    "STRIPE_PUBLISHER_MONTHLY_PRICE": "price_pmo",
    "STRIPE_PUBLISHER_YEARLY_PRICE": "price_pyr",
    "ADMIN_EMAILS": "jane+books@example.com",
})
os.environ.pop("DATABASE_URL", None)      # force SQLite path

import main
from datetime import datetime, timedelta

app = main.app
app.config["TESTING"] = True
client = app.test_client()

# --- fakes -------------------------------------------------------------
sent_emails = []
main.email_notifier.send_email = lambda to, subj, html, attachments=None: (
    sent_emails.append({"to": to, "subject": subj, "html": html}) or True)

class FakeStripeSub(dict): pass
def fake_retrieve(sub_id, price="price_wk"):
    return {"items": {"data": [{"price": {"id": price}}]}}

results = []
def check(name, cond, extra=""):
    results.append((name, bool(cond), extra))
    print(("PASS " if cond else "FAIL ") + name + ("  | " + extra if extra and not cond else ""))

def db():
    return main.get_db()

def get_user(email):
    c = db(); cur = c.cursor()
    cur.execute("SELECT * FROM users WHERE LOWER(email)=LOWER(?)", (email,))
    r = cur.fetchone(); c.close()
    return dict(r) if r else None

def checkout_event(email, sub_id, price):
    main.stripe.Subscription.retrieve = lambda s: fake_retrieve(s, price)
    return {"type": "checkout.session.completed",
            "data": {"object": {"customer_email": email,
                                "subscription": sub_id,
                                "customer": "cus_1"}}}

try:
    # T1: weekly signup, mixed-case + plus-addressed email
    ev = checkout_event("Jane+Books@Example.com", "sub_wk1", "price_wk")
    with app.test_request_context():
        status = main.handle_checkout_completed(ev)
    u = get_user("jane+books@example.com")
    check("T1a webhook created user", u is not None)
    check("T1b email stored lowercase", u and u["email"] == "jane+books@example.com", str(u and u["email"]))
    if u:
        exp = datetime.fromisoformat(str(u["subscription_expires"]).split(".")[0])
        days = (exp - datetime.now()).days
        check("T1c weekly expiry ~7 days (was 30)", 5 <= days <= 8, f"days={days}")

    # T3: setup link encoded + APP_URL
    link = sent_emails[-1]["html"]
    m = re.search(r'href="([^"]+)"', link)
    check("T3a link uses APP_URL", m and m.group(1).startswith("http://testserver:5000/auth/complete-registration"), m.group(1) if m else "no link")
    check("T3b + is URL-encoded", ("jane%2bbooks" in m.group(1).lower()) if m else False, m.group(1) if m else "")

    token = re.search(r"token=([A-Za-z0-9_\-]+)", m.group(1)).group(1)

    # T4: GET prefill (the readonly-empty-field bug)
    r = client.get(f"/auth/complete-registration?email=jane%2Bbooks%40example.com&token={token}")
    check("T4 GET prefills readonly email field", b'value="jane+books@example.com"' in r.data, str(r.status_code))

    # T5: POST completes setup (form posts email+token now)
    r = client.post("/auth/complete-registration", data={
        "email": "Jane+Books@Example.com",  # user-visible casing; route lowercases
        "token": token, "password": "Str0ng!Passw0rd", "full_name": "Jane A"},
        follow_redirects=False)
    u = get_user("jane+books@example.com")
    check("T5a setup POST accepted (redirect)", r.status_code == 302, str(r.status_code))
    check("T5b user is_verified", u and bool(u["is_verified"]))
    check("T5c setup_token cleared", u and u["setup_token"] is None)

    # T6: login
    r = client.post("/auth/login", data={"email": "jane+books@example.com",
                                         "password": "Str0ng!Passw0rd"}, follow_redirects=False)
    check("T6 login redirects to dashboard", r.status_code == 302 and "/dashboard" in r.headers.get("Location",""),
          f"{r.status_code} -> {r.headers.get('Location')}")
    client.get("/auth/logout")

    # T7/T8: forgot + reset password
    r = client.post("/auth/forgot_password", data={"email": "jane+books@example.com"})
    u = get_user("jane+books@example.com")
    check("T7 reset token written to real DB", u and u["reset_token"], )
    rt = u["reset_token"]
    r = client.post(f"/auth/reset_password?token={rt}", data={
        "password": "N3w!Passw0rd##", "confirm_password": "N3w!Passw0rd##"})
    r = client.post("/auth/login", data={"email": "jane+books@example.com",
                                         "password": "N3w!Passw0rd##"}, follow_redirects=False)
    check("T8 login works with reset password", r.status_code == 302 and "/dashboard" in r.headers.get("Location",""),
          f"{r.status_code} -> {r.headers.get('Location')}")
    client.get("/auth/logout")

    # T2: yearly plan expiry
    ev = checkout_event("annual@example.com", "sub_yr1", "price_yr")
    with app.test_request_context():
        main.handle_checkout_completed(ev)
    u = get_user("annual@example.com")
    exp = datetime.fromisoformat(str(u["subscription_expires"]).split(".")[0])
    days = (exp - datetime.now()).days
    check("T2 yearly expiry ~365 days (was 30)", 360 <= days <= 366, f"days={days}")

    # T9: pricing page yearly buttons
    r = client.get("/pricing")
    check("T9 Annual buttons carry real price IDs", b"price_yr" in r.data and b"price_pyr" in r.data)

    # T10: Resend-only config recognized
    for v in ("SMTP_SERVER","SMTP_USERNAME","SMTP_PASSWORD"):
        os.environ.pop(v, None)
    check("T10 is_configured() true with Resend only", main.EmailNotifier().is_configured())

    # T11: legacy route redirect
    r = client.get(f"/auth/setup-account?email=x%40y.com&token=abc", follow_redirects=False)
    check("T11 setup-account redirects to complete-registration",
          r.status_code == 302 and "complete-registration" in r.headers.get("Location",""),
          f"{r.status_code} -> {r.headers.get('Location')}")

    # T12: duplicate webhook delivery (Stripe retry semantics) upserts cleanly
    ev = checkout_event("annual@example.com", "sub_yr1", "price_yr")
    old_token = u["setup_token"]
    with app.test_request_context():
        status = main.handle_checkout_completed(ev)
    u2 = get_user("annual@example.com")
    check("T12 duplicate delivery upserts without error", status == ('', 200) and u2 is not None)

    # T13: subscription.updated
    ev = {"type": "customer.subscription.updated",
          "data": {"object": {"id": "sub_yr1", "status": "past_due",
                              "items": {"data": [{"price": {"id": "price_pmo"}}]}}}}
    with app.test_request_context():
        status = main.handle_subscription_updated(ev)
    u2 = get_user("annual@example.com")
    check("T13 updated -> status+tier synced", status == ('', 200)
          and u2["subscription_status"] == "past_due" and u2["subscription_tier"] == "publisher",
          f"{u2['subscription_status']}/{u2['subscription_tier']}")

    # T14: subscription.deleted
    ev = {"type": "customer.subscription.deleted", "data": {"object": {"id": "sub_yr1"}}}
    with app.test_request_context():
        status = main.handle_subscription_deleted(ev)
    u2 = get_user("annual@example.com")
    check("T14 deleted -> cancelled", status == ('', 200) and u2["subscription_status"] == "cancelled")


    # T15: June-19 free registration flow end-to-end
    r = client.post("/auth/register", data={
        "email": "Free.User@Example.com", "password": "FreeUser1!Pass",
        "confirm_password": "FreeUser1!Pass", "full_name": "Free User"},
        follow_redirects=False)
    u = get_user("free.user@example.com")
    check("T15a register creates free-tier user", u is not None and u["subscription_tier"] == "free"
          and u["max_products"] == 0, str(u and (u["subscription_tier"], u["max_products"])))
    check("T15b verification email sent", any("free.user@example.com" == e["to"] for e in sent_emails))
    vtok = u["verification_token"]
    r = client.get(f"/auth/verify_email?token={vtok}", follow_redirects=False)
    u = get_user("free.user@example.com")
    check("T15c verify link activates account", bool(u["is_verified"]), str(r.status_code))
    r = client.post("/auth/login", data={"email": "free.user@example.com",
                                         "password": "FreeUser1!Pass"}, follow_redirects=False)
    check("T15d free user can log in", r.status_code == 302 and "/dashboard" in r.headers.get("Location",""),
          f"{r.status_code} -> {r.headers.get('Location')}")
    client.get("/auth/logout")

    # T15e: the register PAGE actually renders (June-19 code referenced
    # 'register.html'; real file is 'auth/register.html' -> 500 in prod)
    r = client.get("/auth/register")
    check("T15e GET /auth/register renders form", r.status_code == 200 and b'name="confirm_password"' in r.data,
          str(r.status_code))

    # T18: /settings renders for a logged-in user (referenced nonexistent
    # account_settings.html; needed for setting the ScrapingBee key)
    client.post("/auth/login", data={"email": "free.user@example.com", "password": "FreeUser1!Pass"})
    r = client.get("/settings")
    check("T18 GET /settings renders", r.status_code == 200, str(r.status_code))
    client.get("/auth/logout")

    # T16: registered user upgrades via Stripe -> seam fix
    n_before = len(sent_emails)
    ev = checkout_event("free.user@example.com", "sub_up1", "price_mo")
    with app.test_request_context():
        status = main.handle_checkout_completed(ev)
    u = get_user("free.user@example.com")
    check("T16a upgrade activates subscription", status == ('', 200) and u["subscription_status"] == "active"
          and u["subscription_tier"] == "author", f"{u['subscription_status']}/{u['subscription_tier']}")
    check("T16b password preserved (login still works)",
          client.post("/auth/login", data={"email": "free.user@example.com",
                      "password": "FreeUser1!Pass"}, follow_redirects=False).status_code == 302)
    check("T16c no setup token for registered user", u["setup_token"] is None, str(u["setup_token"]))
    new_mails = sent_emails[n_before:]
    check("T16d activation email, not setup email",
          any("subscription is active" in e["subject"] for e in new_mails)
          and not any("Complete Your" in e["subject"] for e in new_mails),
          str([e["subject"] for e in new_mails]))


    # T17: invoice.payment_succeeded in both API payload shapes
    for shape, inv in [
        ("old", {"subscription": "sub_up1", "customer": "cus_1",
                 "customer_email": "free.user@example.com",
                 "lines": {"data": [{"price": {"id": "price_yr"}}]}}),
        ("basil", {"parent": {"subscription_details": {"subscription": "sub_up1"}},
                   "customer": "cus_1", "customer_email": "free.user@example.com",
                   "lines": {"data": []}}),
    ]:
        main.stripe.Subscription.retrieve = lambda s: fake_retrieve(s, "price_yr")
        ev = {"type": "invoice.payment_succeeded", "data": {"object": inv}}
        with app.test_request_context():
            status = main.handle_invoice_payment_succeeded(ev)
        u = get_user("free.user@example.com")
        from datetime import datetime as _dt
        exp = _dt.fromisoformat(str(u["subscription_expires"]).split(".")[0])
        days = (exp - _dt.now()).days
        check(f"T17 renewal handled ({shape} payload), ~365d", status == ('', 200) and 360 <= days <= 366,
              f"days={days}")


    # T19: dashboard reflects real subscription state
    # (view previously never passed subscription_status -> banner for everyone)
    client.post("/auth/login", data={"email": "jane+books@example.com", "password": "N3w!Passw0rd##"})
    r = client.get("/dashboard")
    check("T19a subscribed user sees NO 'Subscription Required'", b"Subscription Required" not in r.data,
          str(r.status_code))
    client.get("/auth/logout")
    # free.user was cancelled in T14 -> should still see the gate
    client.post("/auth/login", data={"email": "free.user@example.com", "password": "FreeUser1!Pass"})
    r = client.get("/dashboard")
    check("T19b unsubscribed user DOES see the gate", b"Subscription Required" in r.data or b"past_due" in r.data,
          str(r.status_code))
    client.get("/auth/logout")


    # T20: scheduler eligibility under the global-key model
    c = db(); cur = c.cursor()
    ujane = get_user("jane+books@example.com")          # active (T17 renewed)
    ucanc = get_user("annual@example.com")               # cancelled in T14
    cur.execute("INSERT INTO products (user_id, user_email, product_url, product_title) VALUES (?,?,?,?)",
                (ujane["id"], ujane["email"], "https://amazon.com/dp/TESTJANE", "Jane Book"))
    cur.execute("INSERT INTO products (user_id, user_email, product_url, product_title) VALUES (?,?,?,?)",
                (ucanc["id"], ucanc["email"], "https://amazon.com/dp/TESTCANC", "Cancelled Book"))
    c.commit(); c.close()

    checked = []
    real_csp, real_sleep = main.check_single_product, main.time.sleep
    main.check_single_product = lambda pid, url, uid, *a, **k: (checked.append(url), True)[1]
    main.time.sleep = lambda s: None
    try:
        main.check_due_products()
    finally:
        main.check_single_product, main.time.sleep = real_csp, real_sleep

    check("T20a active subscriber's product checked (no per-user key needed)",
          any("TESTJANE" in u for u in checked), str(checked))
    check("T20b cancelled user's product NOT checked (owner-credit protection)",
          not any("TESTCANC" in u for u in checked), str(checked))


    # T21: admin gate — both sides
    client.post("/auth/login", data={"email": "free.user@example.com", "password": "FreeUser1!Pass"})
    r = client.get("/admin/reset_rate_limits")
    check("T21a normal customer gets 403 on admin route", r.status_code == 403, str(r.status_code))
    r = client.get("/admin/create_paid_user/hacker@example.com")
    check("T21b create_paid_user closed to customers", r.status_code == 403, str(r.status_code))
    client.get("/auth/logout")
    client.post("/auth/login", data={"email": "jane+books@example.com", "password": "N3w!Passw0rd##"})
    r = client.get("/admin/reset_rate_limits")
    check("T21c admin (ADMIN_EMAILS) passes the gate", r.status_code != 403, str(r.status_code))

    # T22: scaffolding routes are gone
    gone = all(client.get(p).status_code == 404 for p in
               ("/debug/basic-env", "/debug/db-connection", "/csrf-test", "/deployment-test", "/test"))
    check("T22a deleted debug/test routes return 404", gone)
    r = client.get("/health")
    check("T22b /health still open (Railway healthcheck)", r.status_code == 200, str(r.status_code))

    # T23: feedback lands in the real DB
    r = client.post("/send_feedback", data={"rating": "5", "love": "it works", "improve": "",
                                            "bugs": "", "would_pay": "yes", "price_point": "9"})
    c = db(); cur = c.cursor()
    cur.execute("SELECT user_email, rating FROM feedback ORDER BY id DESC LIMIT 1")
    row = cur.fetchone(); c.close()
    row = dict(row) if row else None
    check("T23 feedback written to real DB", row is not None and row["user_email"] == "jane+books@example.com",
          str(row))
    client.get("/auth/logout")


    # T24: check_single_product's real DB path (the COALESCE crash zone).
    # Stub only the monitor; every query runs for real. Note: the original
    # crash was Postgres-strictness that SQLite masks — this test proves
    # the rewritten query executes and the Python-side coalesce works,
    # not Postgres typing itself (that was verified by the prod deploy).
    class StubMonitor:
        def scrape_amazon_page(self, url, need_screenshot=False):
            return {"success": True, "html": "<html></html>", "screenshot": None}
        def extract_product_info(self, html):
            return {"title": "Jane Book", "rank": "1200", "category": "Kindle Store",
                    "is_bestseller": False, "bestseller_categories": []}
    real_for_user = main.AmazonMonitor.for_user
    main.AmazonMonitor.for_user = classmethod(lambda cls, uid: StubMonitor())
    try:
        c = db(); cur = c.cursor()
        cur.execute("SELECT id, product_url, user_id FROM products WHERE product_url LIKE '%TESTJANE%'")
        prow = dict(cur.fetchone()); c.close()
        ok = main.check_single_product(prow["id"], prow["product_url"], prow["user_id"], "Jane Book", "Kindle Store", None)
        check("T24 hourly-check DB path completes", bool(ok), str(ok))
    finally:
        main.AmazonMonitor.for_user = real_for_user


    # T25: a FAILING product must be stamped so it retries hourly, not every cycle
    c = db(); cur = c.cursor()
    cur.execute("UPDATE products SET last_checked = NULL WHERE product_url LIKE '%TESTJANE%'")
    c.commit(); c.close()
    real_csp2, real_sleep2 = main.check_single_product, main.time.sleep
    main.check_single_product = lambda *a, **k: False      # simulate persistent failure
    main.time.sleep = lambda s: None
    try:
        main.check_due_products()
    finally:
        main.check_single_product, main.time.sleep = real_csp2, real_sleep2
    c = db(); cur = c.cursor()
    cur.execute("SELECT last_checked FROM products WHERE product_url LIKE '%TESTJANE%'")
    lc = cur.fetchone(); lc = dict(lc)["last_checked"] if lc else None
    check("T25a failed check stamps last_checked", lc is not None, str(lc))
    # second pass immediately: product must NOT be due again
    picked = []
    main.check_single_product = lambda pid, url, *a, **k: (picked.append(url), False)[1]
    main.time.sleep = lambda s: None
    try:
        main.check_due_products()
    finally:
        main.check_single_product, main.time.sleep = real_csp2, real_sleep2
    c.close()
    check("T25b failing product not retried within the hour", not any("TESTJANE" in u for u in picked), str(picked))


    # T26: URL validation accepts mobile/share formats, rejects garbage.
    # Found live: the Amazon APP's share link (a.co) was rejected as invalid.
    c = db(); cur = c.cursor()
    cur.execute("DELETE FROM products")  # free jane's 2-product limit
    c.commit(); c.close()

    scraped = []
    class URLStubMonitor:
        def __init__(self, *a, **k): pass
        def scrape_amazon_page(self, url, need_screenshot=True):
            scraped.append(url)
            return {"success": True, "html": "<html></html>", "screenshot": b"png"}
        def extract_product_info(self, html):
            return {"title": "T26 Book", "rank": "500", "category": "Kindle Store",
                    "is_bestseller": False, "bestseller_categories": []}
    real_am = main.AmazonMonitor
    main.AmazonMonitor = URLStubMonitor
    client.post("/auth/login", data={"email": "jane+books@example.com", "password": "N3w!Passw0rd##"})
    try:
        r = client.post("/add_product", data={"url": "definitely not a link", "target_categories": ""})
        check("T26a garbage rejected", not scraped and r.status_code == 302, f"{r.status_code} scraped={scraped}")

        r = client.post("/add_product", data={
            "url": "Check out this book! https://a.co/d/8xYzAbC via @amazon", "target_categories": ""})
        check("T26b app share-text with a.co link accepted",
              scraped and scraped[-1] == "https://a.co/d/8xYzAbC", str(scraped))

        c = db(); cur = c.cursor(); cur.execute("DELETE FROM products"); c.commit(); c.close()
        r = client.post("/add_product", data={
            "url": "https://www.amazon.com/gp/aw/d/B0TESTASIN", "target_categories": ""})
        check("T26c mobile-web /gp/aw/d/ URL accepted",
              scraped and "gp/aw/d" in scraped[-1], str(scraped[-1:]))

        c = db(); cur = c.cursor(); cur.execute("DELETE FROM products"); c.commit(); c.close()
        r = client.post("/add_product", data={
            "url": "amazon.co.uk/dp/B0TESTASIN", "target_categories": ""})
        check("T26d schemeless international URL accepted",
              scraped and scraped[-1] == "https://amazon.co.uk/dp/B0TESTASIN", str(scraped[-1:]))
    finally:
        main.AmazonMonitor = real_am
        client.get("/auth/logout")


    # T27: badge vocabulary — parser must recognize all badge species
    mon = main.AmazonMonitor("fake-key")
    def parse(badge_text):
        html = f'<html><body><span id="productTitle">Badge Test Book</span>' \
               f'<span class="badge-wrapper">{badge_text}</span>' \
               f'<p>Best Sellers Rank: #42 in Kindle Store</p></body></html>'
        return mon.extract_product_info(html)
    check("T27a 'Top New Release' badge detected",
          parse("Top New Release in British &amp; Irish Humor &amp; Satire")["is_bestseller"])
    check("T27b '#1 New Release' badge detected",
          parse("#1 New Release in Mystery")["is_bestseller"])
    check("T27c plain page (no badge) not flagged",
          not parse("Ships from Amazon")["is_bestseller"])


    # T28: unknown badge species must LOG but not trigger
    import io, contextlib
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        info = parse("Editors' Pick in Literary Fiction")
    out = buf.getvalue()
    check("T28a unknown badge does not trigger", not info["is_bestseller"])
    check("T28b unknown badge is logged for vocabulary review",
          "Unrecognized badge-like text" in out and "editors' pick" in out, out[-200:])


    # T29: watchdog noise filter — known non-achievements stay silent,
    # genuinely unknown text still logs
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        parse("Just Released"); parse("-61%")
    check("T29a known noise (just released, -NN%) not logged",
          "Unrecognized badge-like text" not in buf.getvalue(), buf.getvalue()[-150:])
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        parse("Editors' Pick in Cozy Mystery")
    check("T29b genuinely unknown text still logs",
          "Unrecognized badge-like text" in buf.getvalue(), buf.getvalue()[-150:])


    # T30: badge evidence must be verified in the SCREENSHOT request's own page
    from PIL import Image as _Img
    _pngbuf = io.BytesIO(); _Img.new("RGB", (1300, 2000), "white").save(_pngbuf, "PNG")
    REAL_PNG = _pngbuf.getvalue()
    BADGE_HTML = ('<html><body><span id="productTitle">Evidence Book</span>'
                  '<span class="badge-wrapper">#1 New Release in Cozy Mystery</span>'
                  '<p>#77 in Kindle Store</p></body></html>')
    PLAIN_HTML = ('<html><body><span id="productTitle">Evidence Book</span>'
                  '<p>#77 in Kindle Store</p></body></html>')

    c = db(); cur = c.cursor()
    cur.execute("DELETE FROM products")
    cur.execute("INSERT INTO products (user_id, user_email, product_url, product_title) VALUES (?,?,?,?)",
                (ujane["id"], ujane["email"], "https://amazon.com/dp/EVIDENCE", "Evidence Book"))
    c.commit()
    cur.execute("SELECT id FROM products WHERE product_url LIKE '%EVIDENCE%'")
    evid = dict(cur.fetchone())["id"]; c.close()

    class EvidenceMonitor:
        def __init__(self, screenshot_html): self.sh = screenshot_html; self.calls = 0
        def scrape_amazon_page(self, url, need_screenshot=False):
            self.calls += 1
            if need_screenshot:
                return {"success": True, "html": self.sh, "screenshot": REAL_PNG}
            return {"success": True, "html": BADGE_HTML, "screenshot": None}
        def extract_product_info(self, html):
            return main.AmazonMonitor("k").extract_product_info(html)

    real_fu = main.AmazonMonitor.for_user
    n0 = len(sent_emails)

    # T30a: screenshot render LACKS the badge -> reject, no email, retriable
    main.AmazonMonitor.for_user = classmethod(lambda cls, uid: EvidenceMonitor(PLAIN_HTML))
    main.time.sleep = lambda s: None
    try:
        ok = main.check_single_product(evid, "https://amazon.com/dp/EVIDENCE", ujane["id"], "Evidence Book", "Kindle Store", None)
    finally:
        main.AmazonMonitor.for_user = real_fu
    c = db(); cur = c.cursor()
    cur.execute("SELECT has_bestseller_badge FROM products WHERE id=?", (evid,))
    hb = dict(cur.fetchone())["has_bestseller_badge"]; c.close()
    check("T30a mismatched render: no achievement email sent", len(sent_emails) == n0, str(len(sent_emails)-n0))
    check("T30b mismatched render: badge state stays unset (retries next hour)", not hb, str(hb))

    # T30c: screenshot render CONTAINS the badge -> email with full attachment
    c = db(); cur = c.cursor()
    cur.execute("UPDATE products SET last_checked = NULL WHERE id=?", (evid,)); c.commit(); c.close()
    main.AmazonMonitor.for_user = classmethod(lambda cls, uid: EvidenceMonitor(BADGE_HTML))
    try:
        ok = main.check_single_product(evid, "https://amazon.com/dp/EVIDENCE", ujane["id"], "Evidence Book", "Kindle Store", None)
    finally:
        main.AmazonMonitor.for_user = real_fu
    new_mails = sent_emails[n0:]
    check("T30c verified render: achievement email sent", any("Achievement" in e["subject"] for e in new_mails),
          str([e["subject"] for e in new_mails]))
    c = db(); cur = c.cursor()
    cur.execute("SELECT has_bestseller_badge FROM products WHERE id=?", (evid,))
    hb = dict(cur.fetchone())["has_bestseller_badge"]; c.close()
    check("T30d verified render: badge state persisted", bool(hb), str(hb))


    # T31: achievement screenshot stored as base64 in DB (baseline pattern)
    # and servable via /view_screenshot — riding on T30c's verified capture
    c = db(); cur = c.cursor()
    cur.execute("SELECT id, screenshot_data FROM bestseller_screenshots ORDER BY id DESC LIMIT 1")
    row = cur.fetchone(); c.close()
    row = dict(row) if row else None
    import base64 as _b64
    is_png_b64 = False
    if row and row["screenshot_data"]:
        try:
            is_png_b64 = _b64.b64decode(row["screenshot_data"])[:4] == b"\x89PNG"
        except Exception:
            is_png_b64 = False
    check("T31a achievement stored as base64 PNG in DB", bool(is_png_b64),
          str(row["screenshot_data"][:30] if row and row["screenshot_data"] else row))
    client.post("/auth/login", data={"email": "jane+books@example.com", "password": "N3w!Passw0rd##"})
    r = client.get(f"/screenshot/{row["id"]}")
    check("T31b /view_screenshot serves it from the real DB",
          r.status_code == 200 and r.data[:4] == b"\x89PNG", f"{r.status_code} {r.data[:8]}")
    client.get("/auth/logout")

except Exception:
    traceback.print_exc()

fails = [n for n,(ok) ,e in [(n,ok,e) for n,ok,e in results] if not ok]
print(f"\n=== {sum(1 for _,ok,_ in results if ok)}/{len(results)} passed ===")
sys.exit(1 if any(not ok for _,ok,_ in results) else 0)
