"""Before-and-after code examples shown on the Progress page (once a flag is
redeemed) and in the instructor dashboard's Code Examples section.

Each entry has a short plain-language note on why it matters and, for both
the vulnerable and the fixed version, a snippet in Python, JavaScript and
PHP. Snippets are written by hand for teaching -- the Python ones follow the
app's real vulnerable and hardened branches, trimmed down; the JavaScript
(Express) and PHP (PDO) ones are the equivalent patterns.

Authoring format: a line that starts with "!!" is a changed line and gets
highlighted (the marker is stripped before display). Everything else is
shown as written.
"""
from . import flags

LANGUAGES = [("python", "Python"), ("javascript", "JavaScript"), ("php", "PHP")]
_MARK = "!!"


def _parse(text):
    lines = text.strip("\n").split("\n")
    code, highlight = [], []
    for number, line in enumerate(lines, start=1):
        if line.startswith(_MARK):
            highlight.append(number)
            line = line[len(_MARK):]
        code.append(line)
    return {"code": "\n".join(code), "highlight": highlight}


_ENTRIES = {
    "HEADERS_TEACH": {
        "why": "Without framing protection, another site can load this page invisibly inside a frame and trick a signed-in user into clicking things on it (clickjacking). Two response headers tell the browser to refuse. Set them on every page, not just the ones you remember.",
        "vulnerable": {
            "python": r'''
@app.route("/dashboard")
def dashboard():
!!    # Nothing here tells the browser whether another site may frame this page
    return render_template("dashboard.html")
''',
            "javascript": r'''
app.get("/dashboard", (req, res) => {
!!  // Nothing here tells the browser whether another site may frame this page
  res.render("dashboard");
});
''',
            "php": r'''
<?php
// dashboard.php
!!// Nothing here tells the browser whether another site may frame this page
render('dashboard');
''',
        },
        "fixed": {
            "python": r'''
@app.after_request
def add_security_headers(resp):
!!    resp.headers["X-Frame-Options"] = "DENY"
!!    resp.headers["Content-Security-Policy"] = "frame-ancestors 'none'"
    return resp
''',
            "javascript": r'''
app.use((req, res, next) => {
!!  res.set("X-Frame-Options", "DENY");
!!  res.set("Content-Security-Policy", "frame-ancestors 'none'");
  next();
});
''',
            "php": r'''
<?php
// shared bootstrap file, included by every page
!!header('X-Frame-Options: DENY');
!!header("Content-Security-Policy: frame-ancestors 'none'");
''',
        },
    },
    "SQLI_TEACH": {
        "why": "Pasting user input into the SQL text lets the input change the query itself. A parameterized query sends the SQL and the values separately, so the input can only ever be data.",
        "vulnerable": {
            "python": r'''
query = request.args.get("q", "")
!!sql = f"SELECT * FROM meters WHERE meter_code LIKE '%{query}%'"
rows = db.execute(sql).fetchall()
''',
            "javascript": r'''
const q = req.query.q || "";
!!const rows = db.prepare(`SELECT * FROM meters WHERE meter_code LIKE '%${q}%'`).all();
''',
            "php": r'''
$q = $_GET['q'] ?? '';
!!$rows = $pdo->query("SELECT * FROM meters WHERE meter_code LIKE '%$q%'")->fetchAll();
''',
        },
        "fixed": {
            "python": r'''
query = request.args.get("q", "")
!!sql = "SELECT * FROM meters WHERE meter_code LIKE ?"
!!rows = db.execute(sql, (f"%{query}%",)).fetchall()
''',
            "javascript": r'''
const q = req.query.q || "";
!!const rows = db.prepare("SELECT * FROM meters WHERE meter_code LIKE ?").all(`%${q}%`);
''',
            "php": r'''
$q = $_GET['q'] ?? '';
!!$stmt = $pdo->prepare("SELECT * FROM meters WHERE meter_code LIKE ?");
!!$stmt->execute(["%$q%"]);
$rows = $stmt->fetchAll();
''',
        },
    },
    "RXSS_TEACH": {
        "why": "The page prints what the user typed without escaping it, so a script in the search box runs in the victim's browser. Templates escape output by default. Marking a value as safe turns that protection off.",
        "vulnerable": {
            "python": r'''
# view
query = request.args.get("q", "")
return render_template("usage.html", query=query)

# usage.html
!!<p>No results for {{ query|safe }}</p>
''',
            "javascript": r'''
// route
app.get("/usage", (req, res) => {
  res.render("usage", { query: req.query.q || "" });
});

// usage.ejs
!!<p>No results for <%- query %></p>
''',
            "php": r'''
<?php $q = $_GET['q'] ?? ''; ?>
!!<p>No results for <?php echo $q; ?></p>
''',
        },
        "fixed": {
            "python": r'''
# view
query = request.args.get("q", "")
return render_template("usage.html", query=query)

# usage.html
!!<p>No results for {{ query }}</p>
''',
            "javascript": r'''
// route
app.get("/usage", (req, res) => {
  res.render("usage", { query: req.query.q || "" });
});

// usage.ejs
!!<p>No results for <%= query %></p>
''',
            "php": r'''
<?php $q = $_GET['q'] ?? ''; ?>
!!<p>No results for <?php echo htmlspecialchars($q, ENT_QUOTES, 'UTF-8'); ?></p>
''',
        },
    },
    "SXSS_TEACH": {
        "why": "The same mistake as reflected XSS, but the payload is saved and runs for everyone who views it. Output has to be escaped wherever stored input is displayed.",
        "vulnerable": {
            "python": r'''
# saving the nickname
nickname = request.form["nickname"]
db.execute("UPDATE meters SET nickname = ? WHERE id = ?", (nickname, meter_id))

# dashboard.html
!!<h2>{{ meter['nickname']|safe }}</h2>
''',
            "javascript": r'''
// saving the nickname
app.post("/meters/:id/nickname", (req, res) => {
  db.prepare("UPDATE meters SET nickname = ? WHERE id = ?").run(req.body.nickname, req.params.id);
  res.redirect("/dashboard");
});

// dashboard.ejs
!!<h2><%- meter.nickname %></h2>
''',
            "php": r'''
<?php // dashboard.php
$meter = fetchMeter($pdo, $meterId); ?>
!!<h2><?php echo $meter['nickname']; ?></h2>
''',
        },
        "fixed": {
            "python": r'''
# saving the nickname
nickname = request.form["nickname"]
db.execute("UPDATE meters SET nickname = ? WHERE id = ?", (nickname, meter_id))

# dashboard.html
!!<h2>{{ meter['nickname'] }}</h2>
''',
            "javascript": r'''
// saving the nickname
app.post("/meters/:id/nickname", (req, res) => {
  db.prepare("UPDATE meters SET nickname = ? WHERE id = ?").run(req.body.nickname, req.params.id);
  res.redirect("/dashboard");
});

// dashboard.ejs
!!<h2><%= meter.nickname %></h2>
''',
            "php": r'''
<?php // dashboard.php
$meter = fetchMeter($pdo, $meterId); ?>
!!<h2><?php echo htmlspecialchars($meter['nickname'], ENT_QUOTES, 'UTF-8'); ?></h2>
''',
        },
    },
    "WEAKPW_TEACH": {
        "why": "Nothing stops someone choosing a one-character password, which makes guessing trivial. Enforce a minimum length and a mix of character types on the server. A check in the browser alone can be bypassed.",
        "vulnerable": {
            "python": r'''
password = request.form["password"]
!!# No length or complexity check at all
db.execute("INSERT INTO users (email, password_hash) VALUES (?, ?)", (email, hash_password(password)))
''',
            "javascript": r'''
app.post("/signup", async (req, res) => {
  const { email, password } = req.body;
!!  // No length or complexity check at all
  await createUser(email, await hashPassword(password));
  res.redirect("/login");
});
''',
            "php": r'''
$password = $_POST['password'];
!!// No length or complexity check at all
createUser($pdo, $email, password_hash($password, PASSWORD_DEFAULT));
''',
        },
        "fixed": {
            "python": r'''
password = request.form["password"]
!!if len(password) < 8 or password.isalpha() or password.isdigit():
!!    return render_template("signup.html", error="Choose a stronger password."), 400
db.execute("INSERT INTO users (email, password_hash) VALUES (?, ?)", (email, hash_password(password)))
''',
            "javascript": r'''
app.post("/signup", async (req, res) => {
  const { email, password } = req.body;
!!  if (password.length < 8 || /^[A-Za-z]+$/.test(password) || /^[0-9]+$/.test(password)) {
!!    return res.status(400).render("signup", { error: "Choose a stronger password." });
!!  }
  await createUser(email, await hashPassword(password));
  res.redirect("/login");
});
''',
            "php": r'''
$password = $_POST['password'];
!!if (strlen($password) < 8 || ctype_alpha($password) || ctype_digit($password)) {
!!    http_response_code(400);
!!    render('signup', ['error' => 'Choose a stronger password.']);
!!    exit;
!!}
createUser($pdo, $email, password_hash($password, PASSWORD_DEFAULT));
''',
        },
    },
    "RATELIMIT_TEACH": {
        "why": "Unlimited login attempts let an attacker try passwords as fast as the server answers. Counting failures and locking out after a few turns brute force from practical to hopeless. A real lockout also expires after a while.",
        "vulnerable": {
            "python": r'''
user = db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
if user is None or user["password_hash"] != hash_password(password):
!!    return render_template("login.html", error="Invalid login"), 401   # unlimited retries
''',
            "javascript": r'''
app.post("/login", async (req, res) => {
  const user = findUser(req.body.email);
  if (!user || !(await verify(req.body.password, user.hash))) {
!!    return res.status(401).render("login", { error: "Invalid login" });   // unlimited retries
  }
  // ... start the session
});
''',
            "php": r'''
$user = findUser($pdo, $_POST['email']);
if (!$user || !password_verify($_POST['password'], $user['hash'])) {
!!    http_response_code(401);   // unlimited retries
    render('login', ['error' => 'Invalid login']);
    exit;
}
''',
        },
        "fixed": {
            "python": r'''
!!if failed_attempts[email] >= 5:
!!    return render_template("login.html", error="Too many attempts. Try again later."), 429
user = db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
if user is None or user["password_hash"] != hash_password(password):
!!    failed_attempts[email] += 1
    return render_template("login.html", error="Invalid login"), 401
!!failed_attempts.pop(email, None)
''',
            "javascript": r'''
const failed = new Map();
app.post("/login", async (req, res) => {
  const email = req.body.email;
!!  if ((failed.get(email) || 0) >= 5) {
!!    return res.status(429).render("login", { error: "Too many attempts. Try again later." });
!!  }
  const user = findUser(email);
  if (!user || !(await verify(req.body.password, user.hash))) {
!!    failed.set(email, (failed.get(email) || 0) + 1);
    return res.status(401).render("login", { error: "Invalid login" });
  }
!!  failed.delete(email);
});
''',
            "php": r'''
// failedAttempts(), recordFailure() and clearFailures() use a cache or table with an expiry
!!if (failedAttempts($email) >= 5) {
!!    http_response_code(429);
!!    render('login', ['error' => 'Too many attempts. Try again later.']);
!!    exit;
!!}
$user = findUser($pdo, $email);
if (!$user || !password_verify($_POST['password'], $user['hash'])) {
!!    recordFailure($email);
    http_response_code(401);
    render('login', ['error' => 'Invalid login']);
    exit;
}
!!clearFailures($email);
''',
        },
    },
    "FIELDTECH_LOOKUP": {
        "why": "The endpoint returns the whole database row instead of the few fields the tool needs, so anyone who calls it learns the owner's email, billing address and more. Return only what the caller actually needs.",
        "vulnerable": {
            "python": r'''
row = db.execute("SELECT * FROM meters JOIN owners ON owners.id = meters.owner_id WHERE meter_code = ?", (code,)).fetchone()
!!return jsonify(dict(row))   # owner email, billing address, rate... all of it
''',
            "javascript": r'''
app.get("/api/field/meter-lookup", (req, res) => {
  const row = db.prepare("SELECT * FROM meters JOIN owners ON owners.id = meters.owner_id WHERE meter_code = ?").get(req.query.code);
!!  res.json(row);   // owner email, billing address, rate... all of it
});
''',
            "php": r'''
$stmt = $pdo->prepare("SELECT * FROM meters JOIN owners ON owners.id = meters.owner_id WHERE meter_code = ?");
$stmt->execute([$_GET['code']]);
!!echo json_encode($stmt->fetch(PDO::FETCH_ASSOC));   // owner email, billing address, rate... all of it
''',
        },
        "fixed": {
            "python": r'''
row = db.execute("SELECT * FROM meters JOIN owners ON owners.id = meters.owner_id WHERE meter_code = ?", (code,)).fetchone()
return jsonify({
!!    "meter_code": row["meter_code"],
!!    "status": row["status"],
!!    "install_address": row["service_address"],
})
''',
            "javascript": r'''
app.get("/api/field/meter-lookup", (req, res) => {
  const row = db.prepare("SELECT * FROM meters JOIN owners ON owners.id = meters.owner_id WHERE meter_code = ?").get(req.query.code);
  res.json({
!!    meter_code: row.meter_code,
!!    status: row.status,
!!    install_address: row.service_address,
  });
});
''',
            "php": r'''
$stmt = $pdo->prepare("SELECT * FROM meters JOIN owners ON owners.id = meters.owner_id WHERE meter_code = ?");
$stmt->execute([$_GET['code']]);
$row = $stmt->fetch(PDO::FETCH_ASSOC);
echo json_encode([
!!    'meter_code' => $row['meter_code'],
!!    'status' => $row['status'],
!!    'install_address' => $row['service_address'],
]);
''',
        },
    },
    "IDOR_TEACH": {
        "why": "The server trusts the meter ID in the URL and never checks that it belongs to the person asking, so changing the number shows someone else's data. Check ownership on every request.",
        "vulnerable": {
            "python": r'''
@app.route("/api/meters/<int:meter_id>/readings")
@login_required
def readings(meter_id):
    meter = db.execute("SELECT * FROM meters WHERE id = ?", (meter_id,)).fetchone()
!!    # Never checks that this meter belongs to the logged-in user
    return jsonify(get_readings(meter["id"]))
''',
            "javascript": r'''
app.get("/api/meters/:id/readings", requireLogin, (req, res) => {
  const meter = db.prepare("SELECT * FROM meters WHERE id = ?").get(req.params.id);
  if (!meter) return res.sendStatus(404);
!!  // Never checks that this meter belongs to the logged-in user
  res.json(getReadings(meter.id));
});
''',
            "php": r'''
$meter = fetchMeter($pdo, (int) $_GET['id']);
!!// Never checks that this meter belongs to the logged-in user
echo json_encode(getReadings($pdo, $meter['id']));
''',
        },
        "fixed": {
            "python": r'''
@app.route("/api/meters/<int:meter_id>/readings")
@login_required
def readings(meter_id):
    meter = db.execute("SELECT * FROM meters WHERE id = ?", (meter_id,)).fetchone()
!!    if meter["user_id"] != g.user["id"] and g.user["role"] != "admin":
!!        abort(403)
    return jsonify(get_readings(meter["id"]))
''',
            "javascript": r'''
app.get("/api/meters/:id/readings", requireLogin, (req, res) => {
  const meter = db.prepare("SELECT * FROM meters WHERE id = ?").get(req.params.id);
  if (!meter) return res.sendStatus(404);
!!  if (meter.user_id !== req.user.id && req.user.role !== "admin") {
!!    return res.sendStatus(403);
!!  }
  res.json(getReadings(meter.id));
});
''',
            "php": r'''
$meter = fetchMeter($pdo, (int) $_GET['id']);
!!if ($meter['user_id'] !== $user['id'] && $user['role'] !== 'admin') {
!!    http_response_code(403);
!!    exit;
!!}
echo json_encode(getReadings($pdo, $meter['id']));
''',
        },
    },
    "PRIVESC_TEACH": {
        "why": "Being logged in is not the same as being allowed. This admin action only checks for a login, so any customer can call it. Check the role on the server for every privileged action.",
        "vulnerable": {
            "python": r'''
@app.route("/admin/meters/<int:meter_id>/disconnect", methods=["POST"])
@login_required            # proves who you are, not that you may do this
def disconnect_meter(meter_id):
!!    db.execute("UPDATE meters SET status = 'disconnected' WHERE id = ?", (meter_id,))
    db.commit()
''',
            "javascript": r'''
app.post("/admin/meters/:id/disconnect", requireLogin, (req, res) => {
!!  // requireLogin proves who you are, not that you may do this
  db.prepare("UPDATE meters SET status = 'disconnected' WHERE id = ?").run(req.params.id);
  res.sendStatus(204);
});
''',
            "php": r'''
$user = requireLogin();
!!// requireLogin() proves who you are, not that you may do this
$pdo->prepare("UPDATE meters SET status = 'disconnected' WHERE id = ?")->execute([$meterId]);
''',
        },
        "fixed": {
            "python": r'''
@app.route("/admin/meters/<int:meter_id>/disconnect", methods=["POST"])
@login_required
def disconnect_meter(meter_id):
!!    if g.user["role"] != "admin":
!!        abort(403)
    db.execute("UPDATE meters SET status = 'disconnected' WHERE id = ?", (meter_id,))
    db.commit()
''',
            "javascript": r'''
app.post("/admin/meters/:id/disconnect", requireLogin, (req, res) => {
!!  if (req.user.role !== "admin") return res.sendStatus(403);
  db.prepare("UPDATE meters SET status = 'disconnected' WHERE id = ?").run(req.params.id);
  res.sendStatus(204);
});
''',
            "php": r'''
$user = requireLogin();
!!if ($user['role'] !== 'admin') {
!!    http_response_code(403);
!!    exit;
!!}
$pdo->prepare("UPDATE meters SET status = 'disconnected' WHERE id = ?")->execute([$meterId]);
''',
        },
    },
    "TRAVERSAL_TEACH": {
        "why": "Staying inside the bills folder is not enough: the folders inside it belong to different customers. After resolving the path, check that the file's folder belongs to the person asking.",
        "vulnerable": {
            "python": r'''
full_path = os.path.realpath(os.path.join(BILLS_DIR, request.args.get("path", "")))
if os.path.commonpath([BILLS_DIR, full_path]) != BILLS_DIR:   # stays inside bills/
    abort(403)
!!# ...but never checks WHOSE folder it is in
return send_file(full_path)
''',
            "javascript": r'''
const full = fs.realpathSync(path.join(BILLS_DIR, req.query.path || ""));
if (!full.startsWith(BILLS_DIR + path.sep)) return res.sendStatus(403);   // stays inside bills/
!!// ...but never checks WHOSE folder it is in
res.sendFile(full);
''',
            "php": r'''
$full = realpath(BILLS_DIR . '/' . ($_GET['path'] ?? ''));
if ($full === false || strpos($full, BILLS_DIR . DIRECTORY_SEPARATOR) !== 0) { http_response_code(403); exit; }
!!// ...but never checks WHOSE folder it is in
readfile($full);
''',
        },
        "fixed": {
            "python": r'''
full_path = os.path.realpath(os.path.join(BILLS_DIR, request.args.get("path", "")))
if os.path.commonpath([BILLS_DIR, full_path]) != BILLS_DIR:
    abort(403)
!!owner_folder = os.path.relpath(full_path, BILLS_DIR).split(os.sep)[0]
!!if owner_folder not in own_meter_codes(g.user):
!!    abort(403)
return send_file(full_path)
''',
            "javascript": r'''
const full = fs.realpathSync(path.join(BILLS_DIR, req.query.path || ""));
if (!full.startsWith(BILLS_DIR + path.sep)) return res.sendStatus(403);
!!const ownerFolder = path.relative(BILLS_DIR, full).split(path.sep)[0];
!!if (!ownMeterCodes(req.user).includes(ownerFolder)) return res.sendStatus(403);
res.sendFile(full);
''',
            "php": r'''
$full = realpath(BILLS_DIR . '/' . ($_GET['path'] ?? ''));
if ($full === false || strpos($full, BILLS_DIR . DIRECTORY_SEPARATOR) !== 0) { http_response_code(403); exit; }
!!$ownerFolder = explode(DIRECTORY_SEPARATOR, substr($full, strlen(BILLS_DIR) + 1))[0];
!!if (!in_array($ownerFolder, ownMeterCodes($user), true)) { http_response_code(403); exit; }
readfile($full);
''',
        },
    },
    "SESSIONID_TEACH": {
        "why": "Session tokens handed out in order can be guessed: if yours is 100250, someone else's is nearby. Tokens must come from a cryptographically secure random generator.",
        "vulnerable": {
            "python": r'''
_counter = itertools.count(100000)

def issue_session_token():
!!    return str(next(_counter))
''',
            "javascript": r'''
let counter = 100000;

function issueSessionToken() {
!!  return String(counter++);
}
''',
            "php": r'''
function issueSessionToken(): string {
    static $counter = 100000;
!!    return (string) $counter++;
}
''',
        },
        "fixed": {
            "python": r'''
import secrets

def issue_session_token():
!!    return secrets.token_hex(24)
''',
            "javascript": r'''
const crypto = require("crypto");

function issueSessionToken() {
!!  return crypto.randomBytes(24).toString("hex");
}
''',
            "php": r'''
function issueSessionToken(): string {
!!    return bin2hex(random_bytes(24));
}
''',
        },
    },
    "PLAINTEXT_TEACH": {
        "why": "Anything sent over plain HTTP, a password included, can be read by anyone on the network path. Serve everything over HTTPS and redirect HTTP to it. In production, add HSTS as well.",
        "vulnerable": {
            "python": r'''
@app.route("/login", methods=["GET", "POST"])
def login():
!!    # Answers on plain HTTP exactly as it does on HTTPS: the password crosses the network unencrypted
    ...
''',
            "javascript": r'''
app.post("/login", async (req, res) => {
!!  // Answers on plain HTTP exactly as it does on HTTPS: the password crosses the network unencrypted
  // ...
});
''',
            "php": r'''
<?php
// login.php
!!// Answers on plain HTTP exactly as it does on HTTPS: the password crosses the network unencrypted
''',
        },
        "fixed": {
            "python": r'''
@app.before_request
def force_https():
!!    if not request.is_secure:
!!        return redirect(request.url.replace("http://", "https://", 1), code=308)
''',
            "javascript": r'''
// with app.set("trust proxy", true) when behind a proxy
app.use((req, res, next) => {
!!  if (!req.secure) return res.redirect(308, "https://" + req.headers.host + req.originalUrl);
  next();
});
''',
            "php": r'''
<?php
// shared bootstrap file, included by every page
!!if (empty($_SERVER['HTTPS']) || $_SERVER['HTTPS'] === 'off') {
!!    header('Location: https://' . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'], true, 308);
!!    exit;
!!}
''',
        },
    },
    "BUSLOGIC_TEACH": {
        "why": "The server lets the client decide how many units a payment buys. Any value that affects money must be recomputed on the server from trusted inputs, never taken from the request.",
        "vulnerable": {
            "python": r'''
amount = float(request.form["amount_paid"])
override = request.form.get("units_credited")
!!units = float(override) if override else round(amount / RATE, 2)
''',
            "javascript": r'''
const amount = Number(req.body.amount_paid);
const override = req.body.units_credited;
!!const units = override ? Number(override) : Math.round((amount / RATE) * 100) / 100;
''',
            "php": r'''
$amount = (float) $_POST['amount_paid'];
!!$units = !empty($_POST['units_credited']) ? (float) $_POST['units_credited'] : round($amount / RATE, 2);
''',
        },
        "fixed": {
            "python": r'''
amount = float(request.form["amount_paid"])
!!units = round(amount / RATE, 2)   # always recomputed on the server
''',
            "javascript": r'''
const amount = Number(req.body.amount_paid);
!!const units = Math.round((amount / RATE) * 100) / 100;   // always recomputed on the server
''',
            "php": r'''
$amount = (float) $_POST['amount_paid'];
!!$units = round($amount / RATE, 2);   // always recomputed on the server
''',
        },
    },
    "ERRHANDLING_TEACH": {
        "why": "Raw database errors show attackers the structure of your queries and make injection much easier. Log the detail on the server and show the user a generic message.",
        "vulnerable": {
            "python": r'''
try:
    rows = db.execute(sql).fetchall()
except sqlite3.OperationalError as e:
!!    error = str(e)   # the raw driver message, shown to the user
''',
            "javascript": r'''
try {
  rows = db.prepare(sql).all();
} catch (err) {
!!  return res.status(500).send(err.message);   // the raw driver message
}
''',
            "php": r'''
try {
    $rows = $pdo->query($sql)->fetchAll();
} catch (PDOException $e) {
!!    echo $e->getMessage();   // the raw driver message
}
''',
        },
        "fixed": {
            "python": r'''
try:
    rows = db.execute(sql).fetchall()
except sqlite3.OperationalError as e:
!!    app.logger.error("search failed: %s", e)
!!    error = "Something went wrong processing your search. Please try again."
''',
            "javascript": r'''
try {
  rows = db.prepare(sql).all();
} catch (err) {
!!  console.error("search failed:", err);
!!  return res.status(500).send("Something went wrong processing your search. Please try again.");
}
''',
            "php": r'''
try {
    $rows = $pdo->query($sql)->fetchAll();
} catch (PDOException $e) {
!!    error_log($e->getMessage());
!!    echo 'Something went wrong processing your search. Please try again.';
}
''',
        },
    },
    "CSRF_TEACH": {
        "why": "A browser sends your session cookie with any request to the site, even one triggered by a malicious page. A secret per-session token in the form, checked on the server, proves the request really came from your own page.",
        "vulnerable": {
            "python": r'''
@app.route("/account/password", methods=["POST"])
@login_required
def change_password():
!!    # Any POST that carries the session cookie is accepted, wherever it came from
    set_password(g.user, request.form["new_password"])
    return redirect("/account")
''',
            "javascript": r'''
app.post("/account/password", requireLogin, (req, res) => {
!!  // Any POST that carries the session cookie is accepted, wherever it came from
  setPassword(req.user, req.body.new_password);
  res.redirect("/account");
});
''',
            "php": r'''
$user = requireLogin();
!!// Any POST that carries the session cookie is accepted, wherever it came from
setPassword($pdo, $user, $_POST['new_password']);
header('Location: /account');
''',
        },
        "fixed": {
            "python": r'''
def change_password():
!!    token = request.form.get("csrf_token", "")
!!    if not token or not hmac.compare_digest(token, session_csrf_token()):
!!        abort(403)
    set_password(g.user, request.form["new_password"])

# account.html, inside the form
!!<input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
''',
            "javascript": r'''
app.post("/account/password", requireLogin, (req, res) => {
!!  if (!safeEqual(req.body.csrf_token || "", req.session.csrf)) return res.sendStatus(403);
  setPassword(req.user, req.body.new_password);
  res.redirect("/account");
});

// account.ejs, inside the form
!!<input type="hidden" name="csrf_token" value="<%= csrfToken %>">
''',
            "php": r'''
$user = requireLogin();
!!if (!hash_equals($_SESSION['csrf'], $_POST['csrf_token'] ?? '')) {
!!    http_response_code(403);
!!    exit;
!!}
setPassword($pdo, $user, $_POST['new_password']);

// account.php, inside the form
!!<input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf']); ?>">
''',
        },
    },
    "FILEUPLOAD_TEACH": {
        "why": "Accepting any file, of any type and size, under any name, invites malicious uploads and filled disks. Check the type and size on the server, and choose the stored filename yourself.",
        "vulnerable": {
            "python": r'''
uploaded = request.files["firmware"]
!!uploaded.save(os.path.join(UPLOAD_DIR, uploaded.filename))   # any type, any size, any name
''',
            "javascript": r'''
app.post("/admin/meters/:id/firmware", upload.single("firmware"), (req, res) => {
!!  fs.writeFileSync(path.join(UPLOAD_DIR, req.file.originalname), req.file.buffer);   // any type, size or name
  res.sendStatus(204);
});
''',
            "php": r'''
!!move_uploaded_file($_FILES['firmware']['tmp_name'], UPLOAD_DIR . '/' . $_FILES['firmware']['name']);   // any type, size or name
''',
        },
        "fixed": {
            "python": r'''
uploaded = request.files["firmware"]
!!ext = os.path.splitext(uploaded.filename)[1].lower()
!!uploaded.stream.seek(0, os.SEEK_END)
!!size = uploaded.stream.tell()
!!uploaded.stream.seek(0)
!!if ext not in (".bin", ".hex") or size > 2 * 1024 * 1024:
!!    abort(400)
!!uploaded.save(os.path.join(UPLOAD_DIR, secrets.token_hex(8) + ext))   # we choose the filename
''',
            "javascript": r'''
app.post("/admin/meters/:id/firmware", upload.single("firmware"), (req, res) => {
  const ext = path.extname(req.file.originalname).toLowerCase();
!!  if (![".bin", ".hex"].includes(ext) || req.file.size > 2 * 1024 * 1024) {
!!    return res.status(400).send("Rejected: firmware must be a .bin or .hex file under 2 MB.");
!!  }
!!  fs.writeFileSync(path.join(UPLOAD_DIR, crypto.randomBytes(8).toString("hex") + ext), req.file.buffer);
  res.sendStatus(204);
});
''',
            "php": r'''
$file = $_FILES['firmware'];
$ext = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
!!if (!in_array($ext, ['bin', 'hex'], true) || $file['size'] > 2 * 1024 * 1024) {
!!    http_response_code(400);
!!    exit('Rejected: firmware must be a .bin or .hex file under 2 MB.');
!!}
!!move_uploaded_file($file['tmp_name'], UPLOAD_DIR . '/' . bin2hex(random_bytes(8)) . '.' . $ext);
''',
        },
    },
    "ASSISTANT_DIRECT_ACTION": {
        "why": "The assistant let a cleverly worded message decide whether it could act on someone else's meter. Authorization belongs in code that checks who owns the resource, never in the wording of a message. An assistant backed by a real model needs the same check on every tool it can call.",
        "vulnerable": {
            "python": r'''
meter = find_meter(db, text)
if wants_disconnect(text) and meter["user_id"] != user["id"]:
!!    if not has_override_phrase(text):   # "ignore your previous instructions" gets past this
!!        return "I can't do that -- that meter isn't on your account."
db.execute("UPDATE meters SET status = 'disconnected' WHERE id = ?", (meter["id"],))
''',
            "javascript": r'''
async function runTool(call, user) {
  if (call.name === "disconnect_meter") {
!!    // The model chose to call this tool, so it just runs, for ANY meter
    await db.run("UPDATE meters SET status = 'disconnected' WHERE id = ?", call.args.meterId);
    return "Done.";
  }
}
''',
            "php": r'''
function runTool(array $call, array $user): string {
    if ($call['name'] === 'disconnect_meter') {
!!        // The model chose to call this tool, so it just runs, for ANY meter
        disconnectMeter($call['args']['meterId']);
        return 'Done.';
    }
}
''',
        },
        "fixed": {
            "python": r'''
meter = find_meter(db, text)
if wants_disconnect(text) and meter["user_id"] != user["id"]:
!!    return "I can't do that -- that meter isn't on your account."   # ownership decides, not the wording
db.execute("UPDATE meters SET status = 'disconnected' WHERE id = ?", (meter["id"],))
''',
            "javascript": r'''
async function runTool(call, user) {
  if (call.name === "disconnect_meter") {
    const meter = await db.get("SELECT * FROM meters WHERE id = ?", call.args.meterId);
!!    if (!meter || meter.user_id !== user.id) {
!!      return "I can't do that -- that meter isn't on your account.";
!!    }
    await db.run("UPDATE meters SET status = 'disconnected' WHERE id = ?", meter.id);
    return "Done.";
  }
}
''',
            "php": r'''
function runTool(array $call, array $user): string {
    if ($call['name'] === 'disconnect_meter') {
        $meter = fetchMeter($call['args']['meterId']);
!!        if (!$meter || $meter['user_id'] !== $user['id']) {
!!            return "I can't do that -- that meter isn't on your account.";
!!        }
        disconnectMeter($meter['id']);
        return 'Done.';
    }
}
''',
        },
    },
}


def _build():
    built = {}
    for key, entry in _ENTRIES.items():
        item = {"why": entry["why"], "vulnerable": {}, "fixed": {}}
        for side in ("vulnerable", "fixed"):
            for lang, _label in LANGUAGES:
                item[side][lang] = _parse(entry[side][lang])
        built[key] = item
    return built


EXAMPLES = _build()


def has_example(flag_key):
    return flag_key in EXAMPLES


def example_keys():
    return set(EXAMPLES)


def example_payload(flag_key):
    """JSON-ready example for one flag, or None if it has none yet."""
    item = EXAMPLES.get(flag_key)
    if item is None:
        return None
    category, name = next((c, n) for k, c, n in flags.CATALOG if k == flag_key)
    return {
        "key": flag_key,
        "category": category,
        "name": name,
        "why": item["why"],
        "languages": [{"id": lang, "label": label} for lang, label in LANGUAGES],
        "vulnerable": item["vulnerable"],
        "fixed": item["fixed"],
    }
