"""More code examples, in the same format as code_examples.py."""

ENTRIES_A = {
    "HEADERS_EXERCISE": {
        "why": "The sign-in page is reachable before anyone is logged in, so it is the page a browser meets first, and it shipped with none of the headers that tell the browser how to behave. Strict-Transport-Security, X-Content-Type-Options and a Content-Security-Policy belong on every response.",
        "vulnerable": {
            "python": r'''
@app.route("/login")
def login():
!!    # Sent with no Strict-Transport-Security, X-Content-Type-Options or Content-Security-Policy
    return render_template("login.html")
''',
            "javascript": r'''
app.get("/login", (req, res) => {
!!  // Sent with no Strict-Transport-Security, X-Content-Type-Options or Content-Security-Policy
  res.render("login");
});
''',
            "php": r'''
<?php
// login.php
!!// Sent with no Strict-Transport-Security, X-Content-Type-Options or Content-Security-Policy
render('login');
''',
        },
        "fixed": {
            "python": r'''
@app.after_request
def add_security_headers(resp):
!!    resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
!!    resp.headers["X-Content-Type-Options"] = "nosniff"
!!    resp.headers["Content-Security-Policy"] = "default-src 'self'"
    return resp
''',
            "javascript": r'''
app.use((req, res, next) => {
!!  res.set("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
!!  res.set("X-Content-Type-Options", "nosniff");
!!  res.set("Content-Security-Policy", "default-src 'self'");
  next();
});
''',
            "php": r'''
<?php
// shared bootstrap file, included by every page
!!header('Strict-Transport-Security: max-age=31536000; includeSubDomains');
!!header('X-Content-Type-Options: nosniff');
!!header("Content-Security-Policy: default-src 'self'");
''',
        },
    },
    "HEADERS_CLICKJACK": {
        "why": "Two gaps combine here. The recharge page can be framed by any other site, and it accepts a field that chooses which meter receives the credit. A hidden frame over a decoy button then makes the victim's own click pay an attacker. Ignore fields the form never sends, and forbid framing.",
        "vulnerable": {
            "python": r'''
meter = own_meter()
!!target_code = request.form.get("target_meter_code")
!!if target_code:
!!    meter = db.execute("SELECT * FROM meters WHERE meter_code = ?", (target_code,)).fetchone()   # any meter, no ownership check
db.execute("UPDATE meters SET balance = balance + ? WHERE id = ?", (units, meter["id"]))
''',
            "javascript": r'''
let meter = ownMeter(req.user);
!!if (req.body.target_meter_code) {
!!  meter = db.prepare("SELECT * FROM meters WHERE meter_code = ?").get(req.body.target_meter_code);   // any meter, no ownership check
!!}
db.prepare("UPDATE meters SET balance = balance + ? WHERE id = ?").run(units, meter.id);
''',
            "php": r'''
$meter = ownMeter($user);
!!if (!empty($_POST['target_meter_code'])) {
!!    $meter = fetchMeterByCode($pdo, $_POST['target_meter_code']);   // any meter, no ownership check
!!}
$pdo->prepare("UPDATE meters SET balance = balance + ? WHERE id = ?")->execute([$units, $meter['id']]);
''',
        },
        "fixed": {
            "python": r'''
meter = own_meter()
!!# target_meter_code is never read: the credit always goes to the caller's own meter
db.execute("UPDATE meters SET balance = balance + ? WHERE id = ?", (units, meter["id"]))

@app.after_request
def forbid_framing(resp):
!!    resp.headers["Content-Security-Policy"] = "frame-ancestors 'none'"
    return resp
''',
            "javascript": r'''
const meter = ownMeter(req.user);
!!// target_meter_code is never read: the credit always goes to the caller's own meter
db.prepare("UPDATE meters SET balance = balance + ? WHERE id = ?").run(units, meter.id);

app.use((req, res, next) => {
!!  res.set("Content-Security-Policy", "frame-ancestors 'none'");
  next();
});
''',
            "php": r'''
$meter = ownMeter($user);
!!// target_meter_code is never read: the credit always goes to the caller's own meter
$pdo->prepare("UPDATE meters SET balance = balance + ? WHERE id = ?")->execute([$units, $meter['id']]);

!!header("Content-Security-Policy: frame-ancestors 'none'");
''',
        },
    },
    "SQLI_EXERCISE": {
        "why": "The same mistake as the meter search, on a different admin page. Finding one injectable search should make you ask where else the same pattern is used. A UNION against this query reads from the alarms table it targets, which is why this flag appears here and not on the meters page.",
        "vulnerable": {
            "python": r'''
query = request.args.get("q", "")
!!sql = ("SELECT alarms.*, meters.meter_code FROM alarms JOIN meters ON meters.id = alarms.meter_id "
!!       f"WHERE alarms.type LIKE '%{query}%' OR alarms.message LIKE '%{query}%'")
rows = db.execute(sql).fetchall()
''',
            "javascript": r'''
const q = req.query.q || "";
!!const sql = "SELECT alarms.*, meters.meter_code FROM alarms JOIN meters ON meters.id = alarms.meter_id " +
!!  `WHERE alarms.type LIKE '%${q}%' OR alarms.message LIKE '%${q}%'`;
const rows = db.prepare(sql).all();
''',
            "php": r'''
$q = $_GET['q'] ?? '';
!!$sql = "SELECT alarms.*, meters.meter_code FROM alarms JOIN meters ON meters.id = alarms.meter_id "
!!     . "WHERE alarms.type LIKE '%$q%' OR alarms.message LIKE '%$q%'";
$rows = $pdo->query($sql)->fetchAll();
''',
        },
        "fixed": {
            "python": r'''
query = request.args.get("q", "")
!!sql = ("SELECT alarms.*, meters.meter_code FROM alarms JOIN meters ON meters.id = alarms.meter_id "
!!       "WHERE alarms.type LIKE ? OR alarms.message LIKE ?")
!!rows = db.execute(sql, (f"%{query}%", f"%{query}%")).fetchall()
''',
            "javascript": r'''
const q = req.query.q || "";
!!const sql = "SELECT alarms.*, meters.meter_code FROM alarms JOIN meters ON meters.id = alarms.meter_id " +
!!  "WHERE alarms.type LIKE ? OR alarms.message LIKE ?";
!!const rows = db.prepare(sql).all(`%${q}%`, `%${q}%`);
''',
            "php": r'''
$q = $_GET['q'] ?? '';
!!$stmt = $pdo->prepare("SELECT alarms.*, meters.meter_code FROM alarms JOIN meters ON meters.id = alarms.meter_id "
!!     . "WHERE alarms.type LIKE ? OR alarms.message LIKE ?");
!!$stmt->execute(["%$q%", "%$q%"]);
$rows = $stmt->fetchAll();
''',
        },
    },
    "SQLI_BONUS": {
        "why": "The same pattern turns up on a page any customer can reach, with no admin rights needed. A UNION lets someone read every reading in the table, not just their own meter's. When one search is injectable, check every other place that builds a query the same way.",
        "vulnerable": {
            "python": r'''
query = request.args.get("q", "")
!!sql = f"SELECT reading_kwh, source, recorded_at FROM readings WHERE meter_id = {meter_id} AND recorded_at LIKE '%{query}%'"
rows = db.execute(sql).fetchall()
''',
            "javascript": r'''
const q = req.query.q || "";
!!const sql = `SELECT reading_kwh, source, recorded_at FROM readings WHERE meter_id = ${meterId} AND recorded_at LIKE '%${q}%'`;
const rows = db.prepare(sql).all();
''',
            "php": r'''
$q = $_GET['q'] ?? '';
!!$sql = "SELECT reading_kwh, source, recorded_at FROM readings WHERE meter_id = $meterId AND recorded_at LIKE '%$q%'";
$rows = $pdo->query($sql)->fetchAll();
''',
        },
        "fixed": {
            "python": r'''
query = request.args.get("q", "")
!!sql = "SELECT reading_kwh, source, recorded_at FROM readings WHERE meter_id = ? AND recorded_at LIKE ?"
!!rows = db.execute(sql, (meter_id, f"%{query}%")).fetchall()
''',
            "javascript": r'''
const q = req.query.q || "";
!!const sql = "SELECT reading_kwh, source, recorded_at FROM readings WHERE meter_id = ? AND recorded_at LIKE ?";
!!const rows = db.prepare(sql).all(meterId, `%${q}%`);
''',
            "php": r'''
$q = $_GET['q'] ?? '';
!!$stmt = $pdo->prepare("SELECT reading_kwh, source, recorded_at FROM readings WHERE meter_id = ? AND recorded_at LIKE ?");
!!$stmt->execute([$meterId, "%$q%"]);
$rows = $stmt->fetchAll();
''',
        },
    },
    "SQLI_BOOLEAN_BONUS": {
        "why": "Not every injection needs UNION. Making the condition always true removes the filter that limited the results to your own meter. The trailing comment matters, because it throws away the rest of the query, including the closing quote the template adds. Parameterizing fixes this exactly as it fixes UNION.",
        "vulnerable": {
            "python": r'''
query = request.args.get("q", "")
!!sql = f"SELECT reading_kwh, source, recorded_at FROM readings WHERE meter_id = {meter_id} AND recorded_at LIKE '%{query}%'"
# q = ' OR '1'='1' --   becomes:   ... AND recorded_at LIKE '%' OR '1'='1' --%'
rows = db.execute(sql).fetchall()
''',
            "javascript": r'''
const q = req.query.q || "";
!!const sql = `SELECT reading_kwh, source, recorded_at FROM readings WHERE meter_id = ${meterId} AND recorded_at LIKE '%${q}%'`;
// q = ' OR '1'='1' --   becomes:   ... AND recorded_at LIKE '%' OR '1'='1' --%'
const rows = db.prepare(sql).all();
''',
            "php": r'''
$q = $_GET['q'] ?? '';
!!$sql = "SELECT reading_kwh, source, recorded_at FROM readings WHERE meter_id = $meterId AND recorded_at LIKE '%$q%'";
// $q = ' OR '1'='1' --   becomes:   ... AND recorded_at LIKE '%' OR '1'='1' --%'
$rows = $pdo->query($sql)->fetchAll();
''',
        },
        "fixed": {
            "python": r'''
query = request.args.get("q", "")
!!sql = "SELECT reading_kwh, source, recorded_at FROM readings WHERE meter_id = ? AND recorded_at LIKE ?"
# q = ' OR '1'='1' --   is now just a search for that literal text
!!rows = db.execute(sql, (meter_id, f"%{query}%")).fetchall()
''',
            "javascript": r'''
const q = req.query.q || "";
!!const sql = "SELECT reading_kwh, source, recorded_at FROM readings WHERE meter_id = ? AND recorded_at LIKE ?";
// q = ' OR '1'='1' --   is now just a search for that literal text
!!const rows = db.prepare(sql).all(meterId, `%${q}%`);
''',
            "php": r'''
$q = $_GET['q'] ?? '';
!!$stmt = $pdo->prepare("SELECT reading_kwh, source, recorded_at FROM readings WHERE meter_id = ? AND recorded_at LIKE ?");
// $q = ' OR '1'='1' --   is now just a search for that literal text
!!$stmt->execute([$meterId, "%$q%"]);
$rows = $stmt->fetchAll();
''',
        },
    },
    "RXSS_EXERCISE": {
        "why": "Even an error message is output. Repeating what the user typed back inside a 'not found' message, without escaping it, runs any script they put there. Escape everything you print, including the messages around the main page.",
        "vulnerable": {
            "python": r'''
if user is None:
!!    return render_template("forgot_password.html", not_found_email=email)

# forgot_password.html
!!<p>No account found for '{{ not_found_email|safe }}'</p>
''',
            "javascript": r'''
if (!user) {
  return res.render("forgot_password", { notFoundEmail: req.body.email });
}

// forgot_password.ejs
!!<p>No account found for '<%- notFoundEmail %>'</p>
''',
            "php": r'''
<?php $email = $_POST['email'] ?? ''; ?>
<?php if (!findUser($pdo, $email)): ?>
!!<p>No account found for '<?php echo $email; ?>'</p>
<?php endif; ?>
''',
        },
        "fixed": {
            "python": r'''
if user is None:
    return render_template("forgot_password.html", not_found_email=email)

# forgot_password.html
!!<p>No account found for '{{ not_found_email }}'</p>
''',
            "javascript": r'''
if (!user) {
  return res.render("forgot_password", { notFoundEmail: req.body.email });
}

// forgot_password.ejs
!!<p>No account found for '<%= notFoundEmail %>'</p>
''',
            "php": r'''
<?php $email = $_POST['email'] ?? ''; ?>
<?php if (!findUser($pdo, $email)): ?>
!!<p>No account found for '<?php echo htmlspecialchars($email, ENT_QUOTES, 'UTF-8'); ?>'</p>
<?php endif; ?>
''',
        },
    },
    "SXSS_EXERCISE": {
        "why": "Here the saved text runs in an administrator's browser, which is far worse than running in the author's own. Customer-written tickets must be escaped when an admin views them just as carefully as anywhere else. Admin-facing pages need the same output escaping as customer-facing ones.",
        "vulnerable": {
            "python": r'''
# admin_tickets.html
!!<h2>{{ t['subject']|safe }}</h2>
!!<div>{{ t['description']|safe }}</div>
''',
            "javascript": r'''
// admin_tickets.ejs
!!<h2><%- t.subject %></h2>
!!<div><%- t.description %></div>
''',
            "php": r'''
<?php foreach ($tickets as $t): ?>
!!<h2><?php echo $t['subject']; ?></h2>
!!<div><?php echo $t['description']; ?></div>
<?php endforeach; ?>
''',
        },
        "fixed": {
            "python": r'''
# admin_tickets.html
!!<h2>{{ t['subject'] }}</h2>
!!<div>{{ t['description'] }}</div>
''',
            "javascript": r'''
// admin_tickets.ejs
!!<h2><%= t.subject %></h2>
!!<div><%= t.description %></div>
''',
            "php": r'''
<?php foreach ($tickets as $t): ?>
!!<h2><?php echo htmlspecialchars($t['subject'], ENT_QUOTES, 'UTF-8'); ?></h2>
!!<div><?php echo htmlspecialchars($t['description'], ENT_QUOTES, 'UTF-8'); ?></div>
<?php endforeach; ?>
''',
        },
    },
    "WEAKPW_EXERCISE": {
        "why": "Accounts that ship with a shared default password are among the first things an attacker tries. Nothing here made the operators choose their own. Make default or temporary credentials expire: force a new password on the first sign-in.",
        "vulnerable": {
            "python": r'''
SEED_ADMINS = ["ops1@example.com", "ops2@example.com"]
for email in SEED_ADMINS:
!!    create_user(email, password="changeme", role="admin")   # shared default, never has to change
''',
            "javascript": r'''
const SEED_ADMINS = ["ops1@example.com", "ops2@example.com"];
for (const email of SEED_ADMINS) {
!!  createUser(email, "changeme", "admin");   // shared default, never has to change
}
''',
            "php": r'''
$seedAdmins = ['ops1@example.com', 'ops2@example.com'];
foreach ($seedAdmins as $email) {
!!    createUser($pdo, $email, 'changeme', 'admin');   // shared default, never has to change
}
''',
        },
        "fixed": {
            "python": r'''
for email in SEED_ADMINS:
!!    create_user(email, password="changeme", role="admin", must_change_password=True)

@app.before_request
def force_password_change():
!!    if g.user and g.user["must_change_password"] and request.endpoint != "auth.change_password":
!!        return redirect(url_for("auth.change_password"))
''',
            "javascript": r'''
for (const email of SEED_ADMINS) {
!!  createUser(email, "changeme", "admin", { mustChangePassword: true });
}

app.use((req, res, next) => {
!!  if (req.user && req.user.mustChangePassword && req.path !== "/account/password") {
!!    return res.redirect("/account/password");
!!  }
  next();
});
''',
            "php": r'''
foreach ($seedAdmins as $email) {
!!    createUser($pdo, $email, 'changeme', 'admin', true);   // must change on first sign-in
}

// shared bootstrap, runs on every page
!!if ($user && $user['must_change_password'] && $_SERVER['REQUEST_URI'] !== '/account/password') {
!!    header('Location: /account/password');
!!    exit;
!!}
''',
        },
    },
    "WEAKPW_CHANGE": {
        "why": "A password policy that exists on one form but not another is not a policy. Every place a password can be set, whether sign-up, change or reset, has to apply the same strong rules, enforced on the server.",
        "vulnerable": {
            "python": r'''
new_password = request.form["new_password"]
!!# no length or complexity check on this form, whatever sign-up does
db.execute("UPDATE users SET password_hash = ? WHERE id = ?", (hash_password(new_password), g.user["id"]))
''',
            "javascript": r'''
app.post("/account/password", requireLogin, async (req, res) => {
  const { new_password } = req.body;
!!  // no length or complexity check on this form, whatever sign-up does
  db.prepare("UPDATE users SET hash = ? WHERE id = ?").run(await hashPassword(new_password), req.user.id);
  res.redirect("/account");
});
''',
            "php": r'''
$newPassword = $_POST['new_password'];
!!// no length or complexity check on this form, whatever sign-up does
$pdo->prepare("UPDATE users SET hash = ? WHERE id = ?")->execute([password_hash($newPassword, PASSWORD_DEFAULT), $user['id']]);
''',
        },
        "fixed": {
            "python": r'''
new_password = request.form["new_password"]
!!if len(new_password) < 8 or new_password.isalpha() or new_password.isdigit():
!!    return render_template("account.html", error="Choose a stronger password."), 400
db.execute("UPDATE users SET password_hash = ? WHERE id = ?", (hash_password(new_password), g.user["id"]))
''',
            "javascript": r'''
app.post("/account/password", requireLogin, async (req, res) => {
  const { new_password } = req.body;
!!  if (new_password.length < 8 || /^[A-Za-z]+$/.test(new_password) || /^[0-9]+$/.test(new_password)) {
!!    return res.status(400).render("account", { error: "Choose a stronger password." });
!!  }
  db.prepare("UPDATE users SET hash = ? WHERE id = ?").run(await hashPassword(new_password), req.user.id);
  res.redirect("/account");
});
''',
            "php": r'''
$newPassword = $_POST['new_password'];
!!if (strlen($newPassword) < 8 || ctype_alpha($newPassword) || ctype_digit($newPassword)) {
!!    http_response_code(400);
!!    render('account', ['error' => 'Choose a stronger password.']);
!!    exit;
!!}
$pdo->prepare("UPDATE users SET hash = ? WHERE id = ?")->execute([password_hash($newPassword, PASSWORD_DEFAULT), $user['id']]);
''',
        },
    },
    "RATELIMIT_EXERCISE": {
        "why": "Password-reset requests can be hammered just like sign-in attempts: to flood someone's inbox, to probe which addresses exist, or to wear down a weak token. Count requests per address and refuse after a few, with the limit expiring after a while.",
        "vulnerable": {
            "python": r'''
@app.route("/forgot-password", methods=["POST"])
def forgot_password():
    email = request.form["email"]
!!    send_reset_email(email)    # no limit on how often this can be asked for
    return render_template("forgot_password.html", sent=True)
''',
            "javascript": r'''
app.post("/forgot-password", (req, res) => {
  const email = req.body.email;
!!  sendResetEmail(email);    // no limit on how often this can be asked for
  res.render("forgot_password", { sent: true });
});
''',
            "php": r'''
$email = $_POST['email'] ?? '';
!!sendResetEmail($email);    // no limit on how often this can be asked for
render('forgot_password', ['sent' => true]);
''',
        },
        "fixed": {
            "python": r'''
def forgot_password():
    email = request.form["email"]
!!    if reset_attempts[email] >= 5:
!!        return render_template("forgot_password.html", ratelimit_error=True), 429
!!    reset_attempts[email] += 1
    send_reset_email(email)
    return render_template("forgot_password.html", sent=True)
''',
            "javascript": r'''
const attempts = new Map();
app.post("/forgot-password", (req, res) => {
  const email = req.body.email;
!!  if ((attempts.get(email) || 0) >= 5) {
!!    return res.status(429).render("forgot_password", { ratelimitError: true });
!!  }
!!  attempts.set(email, (attempts.get(email) || 0) + 1);
  sendResetEmail(email);
  res.render("forgot_password", { sent: true });
});
''',
            "php": r'''
$email = $_POST['email'] ?? '';
// resetAttempts() and recordResetAttempt() use a cache or table with an expiry
!!if (resetAttempts($email) >= 5) {
!!    http_response_code(429);
!!    render('forgot_password', ['ratelimitError' => true]);
!!    exit;
!!}
!!recordResetAttempt($email);
sendResetEmail($email);
render('forgot_password', ['sent' => true]);
''',
        },
    },
    "DEVADMIN_LEAK": {
        "why": "A note a developer left in the page source, a temporary staging login, was readable by anyone who chose to look. Source comments ship to every visitor. Keep credentials out of code, and don't create staging accounts anywhere they can be reached.",
        "vulnerable": {
            "python": r'''
# login.html
!!<!-- TODO(dev): remove before release. Temp admin for staging:
!!     devadmin@example.com / Dev@2024! -->
<form method="post">...</form>
''',
            "javascript": r'''
// login.ejs
!!<!-- TODO(dev): remove before release. Temp admin for staging:
!!     devadmin@example.com / Dev@2024! -->
<form method="post">...</form>
''',
            "php": r'''
<!-- login.php -->
!!<!-- TODO(dev): remove before release. Temp admin for staging:
!!     devadmin@example.com / Dev@2024! -->
<form method="post">...</form>
''',
        },
        "fixed": {
            "python": r'''
# login.html
!!{# Developer notes go in a template comment, which is never sent to the browser. #}
<form method="post">...</form>

# and no staging account exists outside development
!!if app.config["ENV"] != "development":
!!    assert not user_exists("devadmin@example.com")
''',
            "javascript": r'''
// login.ejs
!!<%# Developer notes go in a template comment, which is never sent to the browser. %>
<form method="post">...</form>

// and no staging account exists outside development
!!if (process.env.NODE_ENV !== "development" && userExists("devadmin@example.com")) {
!!  throw new Error("staging admin must not exist here");
!!}
''',
            "php": r'''
<?php /* login.php: developer notes go in a PHP comment, which is never sent to the browser. */ ?>
<form method="post">...</form>

<?php
// and no staging account exists outside development
!!if (getenv('APP_ENV') !== 'development' && userExists($pdo, 'devadmin@example.com')) {
!!    exit('staging admin must not exist here');
!!}
''',
        },
    },
    "MASSASSIGN_EXERCISE": {
        "why": "The server saves whichever fields arrive in the request, including internal ones the form never lets you edit. Decide on the server which fields a client may change and ignore the rest, instead of trusting the request to only contain what the form shows.",
        "vulnerable": {
            "python": r'''
!!ALLOWED = {"name", "phone", "address_service", "address_billing", "billing_rate"}   # billing_rate is internal
updates = {k: v for k, v in request.get_json().items() if k in ALLOWED}
for field, value in updates.items():
    db.execute(f"UPDATE users SET {field} = ? WHERE id = ?", (value, g.user["id"]))
''',
            "javascript": r'''
!!const ALLOWED = ["name", "phone", "address_service", "address_billing", "billing_rate"];   // billing_rate is internal
for (const [field, value] of Object.entries(req.body)) {
  if (ALLOWED.includes(field)) {
    db.prepare(`UPDATE users SET ${field} = ? WHERE id = ?`).run(value, req.user.id);
  }
}
''',
            "php": r'''
!!$allowed = ['name', 'phone', 'address_service', 'address_billing', 'billing_rate'];   // billing_rate is internal
foreach ($_POST as $field => $value) {
    if (in_array($field, $allowed, true)) {
        $pdo->prepare("UPDATE users SET $field = ? WHERE id = ?")->execute([$value, $user['id']]);
    }
}
''',
        },
        "fixed": {
            "python": r'''
!!ALLOWED = {"name", "phone", "address_service", "address_billing"}   # only what the form actually offers
updates = {k: v for k, v in request.get_json().items() if k in ALLOWED}
for field, value in updates.items():
    db.execute(f"UPDATE users SET {field} = ? WHERE id = ?", (value, g.user["id"]))
''',
            "javascript": r'''
!!const ALLOWED = ["name", "phone", "address_service", "address_billing"];   // only what the form actually offers
for (const [field, value] of Object.entries(req.body)) {
  if (ALLOWED.includes(field)) {
    db.prepare(`UPDATE users SET ${field} = ? WHERE id = ?`).run(value, req.user.id);
  }
}
''',
            "php": r'''
!!$allowed = ['name', 'phone', 'address_service', 'address_billing'];   // only what the form actually offers
foreach ($_POST as $field => $value) {
    if (in_array($field, $allowed, true)) {
        $pdo->prepare("UPDATE users SET $field = ? WHERE id = ?")->execute([$value, $user['id']]);
    }
}
''',
        },
    },
    "ROLE_ESCALATION_BONUS": {
        "why": "A client must never be able to set its own privilege level. When the role is one of the fields the server will accept, anyone can promote themselves to admin with a single request. Roles are changed only by code that checks who is asking.",
        "vulnerable": {
            "python": r'''
!!ALLOWED = {"name", "phone", "address_service", "address_billing", "role"}   # role decides privileges
updates = {k: v for k, v in request.get_json().items() if k in ALLOWED}
for field, value in updates.items():
    db.execute(f"UPDATE users SET {field} = ? WHERE id = ?", (value, g.user["id"]))
''',
            "javascript": r'''
!!const ALLOWED = ["name", "phone", "address_service", "address_billing", "role"];   // role decides privileges
for (const [field, value] of Object.entries(req.body)) {
  if (ALLOWED.includes(field)) {
    db.prepare(`UPDATE users SET ${field} = ? WHERE id = ?`).run(value, req.user.id);
  }
}
''',
            "php": r'''
!!$allowed = ['name', 'phone', 'address_service', 'address_billing', 'role'];   // role decides privileges
foreach ($_POST as $field => $value) {
    if (in_array($field, $allowed, true)) {
        $pdo->prepare("UPDATE users SET $field = ? WHERE id = ?")->execute([$value, $user['id']]);
    }
}
''',
        },
        "fixed": {
            "python": r'''
!!ALLOWED = {"name", "phone", "address_service", "address_billing"}   # role is never client-settable
updates = {k: v for k, v in request.get_json().items() if k in ALLOWED}
for field, value in updates.items():
    db.execute(f"UPDATE users SET {field} = ? WHERE id = ?", (value, g.user["id"]))
''',
            "javascript": r'''
!!const ALLOWED = ["name", "phone", "address_service", "address_billing"];   // role is never client-settable
for (const [field, value] of Object.entries(req.body)) {
  if (ALLOWED.includes(field)) {
    db.prepare(`UPDATE users SET ${field} = ? WHERE id = ?`).run(value, req.user.id);
  }
}
''',
            "php": r'''
!!$allowed = ['name', 'phone', 'address_service', 'address_billing'];   // role is never client-settable
foreach ($_POST as $field => $value) {
    if (in_array($field, $allowed, true)) {
        $pdo->prepare("UPDATE users SET $field = ? WHERE id = ?")->execute([$value, $user['id']]);
    }
}
''',
        },
    },
    "ACCOUNT_IDOR_BONUS": {
        "why": "The request itself names which account to change, so changing that name changes someone else's account. The account being edited must come from the signed-in session, never from a value the client can alter.",
        "vulnerable": {
            "python": r'''
target = g.user
!!other = db.execute("SELECT * FROM users WHERE email = ?", (payload.get("account_email"),)).fetchone()
!!if other is not None:
!!    target = other      # the request decides whose account is changed
db.execute("UPDATE users SET phone = ? WHERE id = ?", (payload["phone"], target["id"]))
''',
            "javascript": r'''
let target = req.user;
!!const other = db.prepare("SELECT * FROM users WHERE email = ?").get(req.body.account_email);
!!if (other) {
!!  target = other;      // the request decides whose account is changed
!!}
db.prepare("UPDATE users SET phone = ? WHERE id = ?").run(req.body.phone, target.id);
''',
            "php": r'''
$target = $user;
!!$other = findUserByEmail($pdo, $_POST['account_email'] ?? '');
!!if ($other) {
!!    $target = $other;      // the request decides whose account is changed
!!}
$pdo->prepare("UPDATE users SET phone = ? WHERE id = ?")->execute([$_POST['phone'], $target['id']]);
''',
        },
        "fixed": {
            "python": r'''
!!target = g.user      # the account always comes from the session, never from the request
db.execute("UPDATE users SET phone = ? WHERE id = ?", (payload["phone"], target["id"]))
''',
            "javascript": r'''
!!const target = req.user;      // the account always comes from the session, never from the request
db.prepare("UPDATE users SET phone = ? WHERE id = ?").run(req.body.phone, target.id);
''',
            "php": r'''
!!$target = $user;      // the account always comes from the session, never from the request
$pdo->prepare("UPDATE users SET phone = ? WHERE id = ?")->execute([$_POST['phone'], $target['id']]);
''',
        },
    },
    "OLDTOKEN_EXERCISE": {
        "why": "A reset link that is only an encoded email address and a time has no secret in it: anyone can write one for any account, and the 'expiry' is never actually checked. A reset token must be signed with a server-side secret, and its age must be verified before it is accepted.",
        "vulnerable": {
            "python": r'''
def make_reset_token(email):
!!    return base64.urlsafe_b64encode(f"{email}:{int(time.time())}".encode()).decode()

def decode_reset_token(token):
    email, _, issued = base64.urlsafe_b64decode(token).decode().rpartition(":")
!!    return email      # no signature to check, and the time is never compared to anything
''',
            "javascript": r'''
function makeResetToken(email) {
!!  return Buffer.from(`${email}:${Math.floor(Date.now() / 1000)}`).toString("base64url");
}

function decodeResetToken(token) {
  const decoded = Buffer.from(token, "base64url").toString();
  const email = decoded.slice(0, decoded.lastIndexOf(":"));
!!  return email;      // no signature to check, and the time is never compared to anything
}
''',
            "php": r'''
function makeResetToken(string $email): string {
!!    return rtrim(strtr(base64_encode($email . ':' . time()), '+/', '-_'), '=');
}

function decodeResetToken(string $token): string {
    $decoded = base64_decode(strtr($token, '-_', '+/'));
!!    return substr($decoded, 0, strrpos($decoded, ':'));   // no signature, and the time is never checked
}
''',
        },
        "fixed": {
            "python": r'''
def make_reset_token(email):
    payload = f"{email}:{int(time.time())}"
!!    sig = hmac.new(SECRET, payload.encode(), "sha256").hexdigest()
    return base64.urlsafe_b64encode(f"{payload}:{sig}".encode()).decode()

def decode_reset_token(token):
    payload, _, sig = base64.urlsafe_b64decode(token).decode().rpartition(":")
!!    if not hmac.compare_digest(sig, hmac.new(SECRET, payload.encode(), "sha256").hexdigest()):
!!        return None
    email, _, issued = payload.rpartition(":")
!!    if time.time() - int(issued) > 3600:
!!        return None
    return email
''',
            "javascript": r'''
const crypto = require("crypto");
const sign = (payload) => crypto.createHmac("sha256", SECRET).update(payload).digest("hex");

function makeResetToken(email) {
  const payload = `${email}:${Math.floor(Date.now() / 1000)}`;
!!  return Buffer.from(`${payload}:${sign(payload)}`).toString("base64url");
}

function decodeResetToken(token) {
  const decoded = Buffer.from(token, "base64url").toString();
  const cut = decoded.lastIndexOf(":");
  const payload = decoded.slice(0, cut);
!!  if (!crypto.timingSafeEqual(Buffer.from(decoded.slice(cut + 1)), Buffer.from(sign(payload)))) return null;
  const issued = Number(payload.slice(payload.lastIndexOf(":") + 1));
!!  if (Date.now() / 1000 - issued > 3600) return null;
  return payload.slice(0, payload.lastIndexOf(":"));
}
''',
            "php": r'''
function makeResetToken(string $email): string {
    $payload = $email . ':' . time();
!!    $sig = hash_hmac('sha256', $payload, SECRET);
    return rtrim(strtr(base64_encode($payload . ':' . $sig), '+/', '-_'), '=');
}

function decodeResetToken(string $token): ?string {
    $decoded = base64_decode(strtr($token, '-_', '+/'));
    $cut = strrpos($decoded, ':');
    $payload = substr($decoded, 0, $cut);
!!    if (!hash_equals(substr($decoded, $cut + 1), hash_hmac('sha256', $payload, SECRET))) return null;
    $issued = (int) substr($payload, strrpos($payload, ':') + 1);
!!    if (time() - $issued > 3600) return null;
    return substr($payload, 0, strrpos($payload, ':'));
}
''',
        },
    },
    "SESSIONREUSE_BONUS": {
        "why": "Logging out only cleared the cookie in the browser; the session itself stayed valid on the server, so anyone who had copied the value could keep using it. Ending a session has to happen on the server: delete the session, or make the lookup refuse one that has been logged out.",
        "vulnerable": {
            "python": r'''
@app.route("/logout", methods=["POST"])
def logout():
!!    # only the browser's cookie goes away; the session row stays valid on the server
    resp = redirect("/login")
    resp.delete_cookie("session")
    return resp
''',
            "javascript": r'''
app.post("/logout", (req, res) => {
!!  // only the browser's cookie goes away; the session row stays valid on the server
  res.clearCookie("session");
  res.redirect("/login");
});
''',
            "php": r'''
<?php
// logout.php
!!setcookie('session', '', time() - 3600, '/');   // only the browser's cookie goes away; the session stays valid
header('Location: /login');
''',
        },
        "fixed": {
            "python": r'''
@app.route("/logout", methods=["POST"])
def logout():
!!    db.execute("DELETE FROM sessions WHERE token = ?", (request.cookies.get("session"),))
!!    db.commit()
    resp = redirect("/login")
    resp.delete_cookie("session")
    return resp
''',
            "javascript": r'''
app.post("/logout", (req, res) => {
!!  db.prepare("DELETE FROM sessions WHERE token = ?").run(req.cookies.session);
  res.clearCookie("session");
  res.redirect("/login");
});
''',
            "php": r'''
<?php
// logout.php
!!$pdo->prepare("DELETE FROM sessions WHERE token = ?")->execute([$_COOKIE['session'] ?? '']);
setcookie('session', '', time() - 3600, '/');
header('Location: /login');
''',
        },
    },
}
