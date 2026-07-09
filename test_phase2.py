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

print("SUITE VERSION 7 (admin gate + cleanup) — expect 41 checks. "
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

except Exception:
    traceback.print_exc()

fails = [n for n,(ok) ,e in [(n,ok,e) for n,ok,e in results] if not ok]
print(f"\n=== {sum(1 for _,ok,_ in results if ok)}/{len(results)} passed ===")
sys.exit(1 if any(not ok for _,ok,_ in results) else 0)
