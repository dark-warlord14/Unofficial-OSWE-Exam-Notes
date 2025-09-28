# Deep Research — Server-Side Vulnerabilities & Dangerous Code Patterns in PHP

Based on extensive research of OWASP standards, CWE classifications, CVE databases, and security documentation, here are the most critical server-side vulnerability classes and their dangerous PHP code patterns:

## Remote Code Execution (RCE)

**Bad Pattern 1: eval() with User Input**[1][2][3]
```php
$code = $_GET['data'];
eval($code);
```
**Explanation:** The eval() function executes strings as PHP code, allowing attackers to run arbitrary commands by injecting malicious PHP code through user input.

**Bad Pattern 2: system() Command Execution**[4][2]
```php
$cmd = $_GET['command'];
system($cmd);
```
**Explanation:** Direct execution of user-controlled input through system() allows attackers to execute operating system commands on the server.

**Bad Pattern 3: Unserialize() Object Injection**[5][6][7][8]
```php
$data = unserialize($_GET['data']);
```
**Explanation:** Deserializing untrusted user input can trigger magic methods (__wakeup, __destruct) leading to arbitrary code execution through object injection attacks.

## SQL Injection

**Bad Pattern 1: Direct String Concatenation**[9][10][11]
```php
$user = $_GET['username'];
$query = "SELECT * FROM users WHERE username = '$user'";
mysqli_query($conn, $query);
```
**Explanation:** Concatenating user input directly into SQL queries allows attackers to manipulate query structure and execute arbitrary SQL commands.

**Bad Pattern 2: Dynamic Query Building**[10][11]
```php
$id = $_GET['id'];
$sql = "SELECT * FROM products WHERE id = " . $id;
mysql_query($sql);
```
**Explanation:** Building queries without parameterization enables attackers to inject SQL code, potentially accessing or modifying database contents.

**Bad Pattern 3: WHERE Clause Injection**[12][10]
```php
$filter = $_POST['filter'];
$query = "SELECT * FROM items WHERE category = '$filter'";
```
**Explanation:** User-controlled WHERE clauses without proper sanitization allow attackers to bypass authentication or access unauthorized data.

## Server-Side Request Forgery (SSRF)

**Bad Pattern 1: file_get_contents() with User URLs**[13][14][15]
```php
$url = $_GET['url'];
$content = file_get_contents($url);
echo $content;
```
**Explanation:** Allowing user-controlled URLs in file_get_contents() enables attackers to make requests to internal services or read local files.

**Bad Pattern 2: cURL with User Input**[14][15][16]
```php
$target = $_POST['target'];
$ch = curl_init($target);
curl_exec($ch);
```
**Explanation:** Using user input as cURL targets allows attackers to probe internal networks, access cloud metadata, or perform port scanning.

**Bad Pattern 3: fopen() with External URLs**[14][17]
```php
$file = $_GET['file'];
$handle = fopen($file, 'r');
```
**Explanation:** Opening user-specified URLs with fopen() can be exploited to access internal resources or sensitive files through various protocols.

## File Upload Vulnerabilities

**Bad Pattern 1: Unrestricted File Upload**[18][19][20][21]
```php
$target = "uploads/" . $_FILES['file']['name'];
move_uploaded_file($_FILES['file']['tmp_name'], $target);
```
**Explanation:** Accepting uploaded files without validation allows attackers to upload executable scripts (PHP shells) that can be accessed via web requests.

**Bad Pattern 2: Insufficient MIME Type Validation**[18][20]
```php
if ($_FILES['upload']['type'] == 'image/jpeg') {
    move_uploaded_file($_FILES['upload']['tmp_name'], $dest);
}
```
**Explanation:** Relying only on client-provided MIME types is insufficient as attackers can easily forge these headers to upload malicious files.

**Bad Pattern 3: Missing File Extension Filtering**[18][22]
```php
$filename = $_FILES['file']['name'];
move_uploaded_file($_FILES['file']['tmp_name'], "uploads/" . $filename);
```
**Explanation:** Not filtering dangerous extensions (.php, .phtml, .exe) allows attackers to upload executable code that can compromise the server.

## XML External Entity (XXE) Attacks

**Bad Pattern 1: SimpleXML Without Entity Disabling**[23][24][25]
```php
$xml = simplexml_load_string($_POST['xml']);
```
**Explanation:** Processing XML without disabling external entities allows attackers to read local files, perform SSRF attacks, or cause denial of service.

**Bad Pattern 2: DOMDocument with External Entities**[23][25][26]
```php
$dom = new DOMDocument();
$dom->loadXML($_GET['xml_data']);
```
**Explanation:** Loading XML documents without libxml_disable_entity_loader(true) enables XXE attacks that can expose sensitive system files.

**Bad Pattern 3: XMLReader with Untrusted Input**[23][26]
```php
$reader = new XMLReader();
$reader->XML($_POST['data']);
```
**Explanation:** XMLReader processing untrusted XML can trigger XXE vulnerabilities when external entity loading is not properly disabled.

## Local File Inclusion (LFI) & Path Traversal

**Bad Pattern 1: Dynamic File Inclusion**[9][27][28][29]
```php
$page = $_GET['page'];
include($page);
```
**Explanation:** Including files based on user input allows attackers to traverse directories using "../" sequences and include arbitrary files for execution.

**Bad Pattern 2: Unsanitized File Paths**[27][29][30]
```php
$file = $_GET['file'];
$content = file_get_contents("data/" . $file);
```
**Explanation:** Concatenating user input to file paths without validation enables directory traversal attacks to read sensitive files like /etc/passwd.

**Bad Pattern 3: Template Inclusion Vulnerability**[9][28]
```php
$template = $_GET['template'];
include("templates/" . $template . ".php");
```
**Explanation:** Even with directory restrictions, null byte injection or directory traversal can bypass protections and include unintended files.

## LDAP Injection

**Bad Pattern 1: Unescaped LDAP Filter**[31][32][33][34]
```php
$username = $_POST['username'];
$filter = "(uid=" . $username . ")";
$search = ldap_search($conn, $base_dn, $filter);
```
**Explanation:** Building LDAP queries without escaping allows attackers to manipulate query logic, bypassing authentication or accessing unauthorized data.

**Bad Pattern 2: Dynamic DN Construction**[31][33]
```php
$user = $_GET['user'];
$dn = "cn=" . $user . ",ou=users,dc=example,dc=com";
ldap_bind($conn, $dn, $password);
```
**Explanation:** Concatenating user input into distinguished names enables injection attacks that can modify LDAP query scope and access controls.

**Bad Pattern 3: Privilege Escalation via Injection**[34]
```php
$level = $_POST['security_level'];
$filter = "(&(directory=docs)(security_level=" . $level . "))";
```
**Explanation:** Unescaped security parameters allow attackers to inject LDAP syntax to bypass access restrictions and view higher-privilege data.

## Cross-Site Request Forgery (CSRF)

**Bad Pattern 1: Missing CSRF Token Validation**[35][36][37][38]
```php
if ($_POST['action'] == 'delete') {
    deleteUser($_POST['user_id']);
}
```
**Explanation:** Processing state-changing actions without CSRF tokens allows attackers to forge requests from authenticated users' browsers.

**Bad Pattern 2: GET Requests for State Changes**[38][39]
```php
if ($_GET['action'] == 'transfer' && $_GET['amount']) {
    transferMoney($_GET['to'], $_GET['amount']);
}
```
**Explanation:** Using GET requests for sensitive operations makes CSRF attacks trivial as attackers can embed malicious requests in images or links.

**Bad Pattern 3: Weak CSRF Protection**[36][40]
```php
$expected_token = md5($_SESSION['user_id']);
if ($_POST['token'] != $expected_token) { /* reject */ }
```
**Explanation:** Predictable CSRF tokens based on user data can be guessed by attackers, making the protection ineffective.

## HTTP Response Splitting & Header Injection

**Bad Pattern 1: Direct Header Setting**[41][42][43][44]
```php
$redirect = $_GET['redirect'];
header("Location: " . $redirect);
```
**Explanation:** Injecting user input into HTTP headers without validation allows CRLF injection attacks that can split responses or inject malicious headers.

**Bad Pattern 2: Cookie Injection**[43][44][45]
```php
$username = $_GET['user'];
header("Set-Cookie: username=" . $username);
```
**Explanation:** User-controlled cookie values enable header injection, potentially allowing XSS, cache poisoning, or session manipulation attacks.

**Bad Pattern 3: Custom Header Injection**[44][46]
```php
$name = $_POST['name'];
header("X-User-Name: " . $name);
```
**Explanation:** Setting custom headers with unvalidated input creates CRLF injection vulnerabilities that can compromise HTTP response integrity.

## Session Management Vulnerabilities

**Bad Pattern 1: Predictable Session IDs**[47][48][49][50]
```php
session_id(md5($_SERVER['REMOTE_ADDR'] . time()));
session_start();
```
**Explanation:** Using predictable algorithms for session IDs makes them vulnerable to brute force attacks or prediction, enabling session hijacking.

**Bad Pattern 2: Missing Session Regeneration**[47][49]
```php
if (authenticate($user, $pass)) {
    $_SESSION['logged_in'] = true; // No session_regenerate_id()
}
```
**Explanation:** Failing to regenerate session IDs after authentication leaves applications vulnerable to session fixation attacks.

**Bad Pattern 3: Insecure Session Storage**[48][51]
```php
session_set_cookie_params(0, '/', '', false, false); // No secure flags
```
**Explanation:** Sessions without HttpOnly and Secure flags are vulnerable to XSS-based theft and transmission over unencrypted connections.

## Weak Random Number Generation

**Bad Pattern 1: rand() for Security Tokens**[52][53][54][55]
```php
$token = rand(100000, 999999);
$_SESSION['csrf_token'] = $token;
```
**Explanation:** Using rand() for security-sensitive values creates predictable tokens vulnerable to brute force or statistical analysis attacks.

**Bad Pattern 2: mt_rand() with Predictable Seeds**[52][53][56]
```php
mt_srand(time());
$password_reset_token = mt_rand();
```
**Explanation:** Mersenne Twister with predictable seeds generates sequences that can be reconstructed by attackers who know the seeding time.

**Bad Pattern 3: Time-based Randomness**[54][57]
```php
$session_id = md5(microtime() . $_SERVER['REMOTE_ADDR']);
```
**Explanation:** Using timestamps as entropy sources creates predictable values that attackers can enumerate or calculate within narrow time windows.

These dangerous patterns represent the most critical server-side vulnerabilities found in PHP applications. Each pattern stems from insufficient input validation, improper use of dangerous functions, or failure to implement secure coding practices. Organizations should implement comprehensive code review processes, use static analysis tools, and follow secure development frameworks to identify and remediate these vulnerabilities.

# Sources:
- [1] Remote Code Execution (RCE) https://www.invicti.com/learn/remote-code-execution-rce/
- [2] What is RCE vulnerability? Remote code execution meaning https://www.wallarm.com/what/the-concept-of-rce-remote-code-execution-attack
- [3] Remote Code Evaluation (Execution) Vulnerability https://www.invicti.com/blog/web-security/remote-code-evaluation-execution/
- [4] PHP Security Best Practices, Vulnerabilities and Attacks https://www.vaadata.com/blog/php-security-best-practices-vulnerabilities-and-attacks/
- [5] What is Object Injection? Exploitations and Security Tips https://www.vaadata.com/blog/what-is-object-injection-exploitations-and-security-best-practices/
- [6] PHP Insecure Deserialization | A Critical Vulnerability ... https://redbotsecurity.com/php-insecure-deserialization/
- [7] phpPgAdmin Deserialization Vulnerability https://www.sonicwall.com/blog/phppgadmin-deserialization-vulnerability
- [8] CVE-2025-29306 – Unauthenticated Remote Code ... https://www.offsec.com/blog/cve-2025-29306/
- [9] PHP Security Code Review Cheat Sheet https://appsec-labs.com/php-security-code-review-cheat-sheet-appsec-labs/
- [10] How To Prevent SQL Injection Vulnerabilities in PHP ... https://www.invicti.com/blog/web-security/how-to-prevent-sql-injection-in-php-applications/
- [11] Prevent SQL injection vulnerabilities in PHP applications ... https://www.acunetix.com/blog/articles/prevent-sql-injection-vulnerabilities-in-php-applications/
- [12] Prevent SQL Injection in PHP with Prepared Statements https://accuweb.cloud/resource/articles/prevent-sql-injection-in-php-with-prepared-statements
- [13] php - Security vulnerabilities with file_get_contents() using ... https://stackoverflow.com/questions/17647585/security-vulnerabilities-with-file-get-contents-using-variable-location
- [14] Understanding the Web Vulnerability Server-Side Request ... https://www.vaadata.com/blog/understanding-web-vulnerability-server-side-request-forgery-1/
- [15] Server-Side Request Forgery (SSRF) | Commerce PHP ... https://developer.adobe.com/commerce/php/development/security/server-side-request-forgery/
- [16] curl_setopt - Manual https://www.php.net/manual/en/function.curl-setopt.php
- [17] Learn about Server Side Request Forgery (SSRF) https://patchstack.com/academy/wordpress/vulnerabilities/server-side-request-forgery/
- [18] CWE-434: Unrestricted Upload of File with Dangerous Type https://cwe.mitre.org/data/definitions/434.html
- [19] PHP move_uploaded_file() Function https://www.w3schools.com/php/func_filesystem_move_uploaded_file.asp
- [20] How to Secure File Upload in PHP Correctly? https://www.ongraph.com/how-to-secure-uploaded-file-over-server-using-php/
- [21] Ultimate Guide to PHP File Upload Security - Inspector.dev https://inspector.dev/ultimate-guide-to-php-file-upload-security/
- [22] File Upload Bypass: Upload Forms Threat Explained https://www.acunetix.com/websitesecurity/upload-forms-threat/
- [23] `libxml_disable_entity_loader` function is deprecated https://php.watch/versions/8.0/libxml_disable_entity_loader-deprecation
- [24] XML injection (XXE) - Unmarshaller - PHP - Knowledge Base https://help.fluidattacks.com/portal/en/kb/articles/criteria-fixes-php-323
- [25] Disabling External Entities in libxml By Default https://externals.io/message/87372
- [26] XML External Entity (XXE) Attacks and How to Avoid Them https://www.invicti.com/blog/web-security/xxe-xml-external-entity-attacks/
- [27] PHP Security 2: Directory Traversal & Code Injection https://www.acunetix.com/websitesecurity/php-security-2/
- [28] File Inclusion and Path Traversal - Web Applications ... https://0xffsec.com/handbook/web-applications/file-inclusion-and-path-traversal/
- [29] Directory Traversal (Path Traversal) https://www.invicti.com/learn/directory-traversal-path-traversal/
- [30] A guide to path traversal and arbitrary file read attacks https://www.yeswehack.com/learn-bug-bounty/practical-guide-path-traversal-attacks
- [31] LDAP Escaping in PHP https://ssojet.com/escaping/ldap-escaping-in-php/
- [32] LDAP Injection in Laravel: Prevention & Secure Coding https://dev.to/pentest_testing_corp/ldap-injection-in-laravel-prevention-secure-coding-1hld
- [33] LDAP injection - PHP - Knowledge Base https://help.fluidattacks.com/portal/en/kb/articles/criteria-fixes-php-107
- [34] LDAP Injection Guide: Types, Examples, Prevention https://brightsec.com/blog/ldap-injection/
- [35] Vulnerabilities / Missing cross-site request forgery protection https://probely.com/vulnerabilities/missing-cross-site-request-forgery-protection/
- [36] CSRF Protection - Laravel 12.x - The PHP Framework For ... https://laravel.com/docs/12.x/csrf
- [37] Cross-Site Request Forgery Prevention Cheat Sheet https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html
- [38] Cross-Site Request Forgery (CSRF) https://www.invicti.com/learn/cross-site-request-forgery-csrf/
- [39] Cross Site Request Forgery (CSRF) https://owasp.org/www-community/attacks/csrf
- [40] CSRF (Cross-site request forgery) attack example and ... https://stackoverflow.com/questions/2526522/csrf-cross-site-request-forgery-attack-example-and-prevention-in-php
- [41] What Is HTTP Response Splitting? How It Works & Examples https://www.twingate.com/blog/glossary/http-response-splitting
- [42] HTTP response header injection https://portswigger.net/kb/issues/00200200_http-response-header-injection
- [43] CRLF Injection https://www.invicti.com/learn/crlf-injection/
- [44] CRLF injection, HTTP response splitting & HTTP header ... https://www.invicti.com/blog/web-security/crlf-http-header/
- [45] HTTP response splitting https://en.wikipedia.org/wiki/HTTP_response_splitting
- [46] CVE-2006-0207 - NVD https://nvd.nist.gov/vuln/detail/CVE-2006-0207
- [47] PHP Session Fixation / Hijacking https://stackoverflow.com/questions/5081025/php-session-fixation-hijacking
- [48] How to Prevent Session Hijacking: Secure PHP Session ... https://www.dopethemes.com/how-to-prevent-session-hijacking-secure-php-session-management/
- [49] Session fixation https://owasp.org/www-community/attacks/Session_fixation
- [50] What Is Session Fixation & How to Prevent It https://www.descope.com/learn/post/session-fixation
- [51] PHP Session Security: Preventing Session Hijacking https://hostadvice.com/blog/web-hosting/php/php-session-security/
- [52] I Forgot Your Password: Randomness Attacks Against PHP ... https://www.usenix.org/system/files/conference/usenixsecurity12/sec12-final218.pdf
- [53] Misc CTF - PRNG Weakness :: hg8's Notes - hg8.sh https://hg8.sh/posts/misc-ctf/PRNG%20Weakness/
- [54] Insecure Randomness https://owasp.org/www-community/vulnerabilities/Insecure_Randomness
- [55] Address insecure random number generation in PHP https://stackoverflow.com/questions/10216141/address-insecure-random-number-generation-in-php
- [56] PHP : Weak random number generator https://derscanner.com/vulnerability-database/PHP-:-Weak-random-number-generator
- [57] Use of Cryptographically Weak Pseudo-Random Number ... https://security.snyk.io/vuln/SNYK-PHP-GUZZLEHTTPOAUTHSUBSCRIBER-8602526
