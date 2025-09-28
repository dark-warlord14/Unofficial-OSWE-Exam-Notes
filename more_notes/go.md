# Deep Research — Server-Side Vulnerabilities & Dangerous Code Patterns in Golang

## SQL Injection Vulnerabilities

**Bad Pattern 1: String concatenation with fmt.Sprintf**
```go
query := fmt.Sprintf("SELECT * FROM users WHERE id = %s", userID)
rows, err := db.Query(query)
```
Explanation: Direct string formatting creates SQL injection vulnerabilities by allowing attackers to inject malicious SQL code through user input[1][2][3].

**Bad Pattern 2: Direct string concatenation**
```go
searchRequest := "(&(objectClass=organizationalPerson)(uid=" + username + "))"
```
Explanation: String concatenation in SQL queries bypasses prepared statement protections, enabling SQL injection attacks[1][4].

**Bad Pattern 3: Using Query with string interpolation**
```go
rows, err := db.Query("SELECT * FROM files WHERE tenant_id = '" + tenantID + "'")
```
Explanation: This pattern allows attackers to manipulate SQL queries by injecting malicious code through the tenantID parameter[1][3].

**Regex (starter pattern):** `fmt\.Sprintf.*SELECT|UPDATE|DELETE|INSERT|Query.*\+.*|".*\+.*userID|tenantID|username`

**Reference(s):** CVE-2023-26125, Go official documentation on SQL injection prevention, StackHawk Golang SQL Injection Guide[1][2][3]

***

## Server-Side Request Forgery (SSRF)

**Bad Pattern 1: Unvalidated URL construction with http.Get**
```go
urlStr := fmt.Sprintf("http://%s.%s/storage/%s.json", tenantID, baseHost, fileID)
resp, err := http.Get(urlStr)
```
Explanation: Direct user input in URL construction allows attackers to redirect requests to arbitrary domains or internal services[5][6].

**Bad Pattern 2: Direct http.Get with user input**
```go
target := c.Query("target")
resp, err := http.Get(target)
```
Explanation: Accepting user-controlled URLs without validation enables SSRF attacks against internal infrastructure[5][6].

**Bad Pattern 3: Client.Get with unvalidated parameters**
```go
client := &http.Client{}
resp, err := client.Get("http://api.internal/" + userParam)
```
Explanation: Concatenating user input directly into HTTP requests can expose internal services to external attackers[5][6].

**Regex (starter pattern):** `http\.Get.*\+|fmt\.Sprintf.*http://|Client\.Get.*userParam|tenantID`

**Reference(s):** CVE-2025-20088, SNYK-GOLANG-GOLANGORGXNETHTTPHTTPPROXY-9058601, Fluid Attacks Go SSRF Knowledge Base[7][5][6]

***

## Command Injection

**Bad Pattern 1: exec.Command with user input**
```go
userInput := req.FormValue("cmd")
cmd := exec.Command(userInput)
cmd.Run()
```
Explanation: Allowing user input to control command execution enables arbitrary command execution on the server[8][9][10].

**Bad Pattern 2: syscall.Exec with unvalidated path**
```go
path, _ := exec.LookPath(userInput)
syscall.Exec(path, args, env)
```
Explanation: User-controlled executable paths in syscall.Exec can lead to privilege escalation and system compromise[8][10].

**Bad Pattern 3: exec.Cmd struct with user input**
```go
cmd := &exec.Cmd{
    Path: userInput,
    Args: []string{"bash", userArg},
}
```
Explanation: Direct user input in Cmd struct fields allows attackers to execute arbitrary commands with application privileges[8][10].

**Regex (starter pattern):** `exec\.Command.*userInput|syscall\.Exec.*userInput|exec\.Cmd.*userInput`

**Reference(s):** Semgrep Go Command Injection, StackHawk Command Injection Guide, Snyk Command Injection Guide[8][9][10]

***

## Path Traversal

**Bad Pattern 1: Direct file path construction**
```go
filename := req.FormValue("file")
content, err := ioutil.ReadFile("/uploads/" + filename)
```
Explanation: Unvalidated file paths enable directory traversal attacks to access files outside the intended directory[11][12][13].

**Bad Pattern 2: filepath.Join without validation**
```go
userPath := c.Query("path")
fullPath := filepath.Join(baseDir, userPath)
file, err := os.Open(fullPath)
```
Explanation: User-controlled paths in filepath operations can bypass security boundaries using "../" sequences[12][14][15].

**Bad Pattern 3: os.Open with user input**
```go
filePath := "/var/data/" + userProvidedPath
file, err := os.Open(filePath)
```
Explanation: Direct concatenation of user input with file paths allows access to arbitrary files on the filesystem[12][13].

**Regex (starter pattern):** `filepath\.Join.*userPath|os\.Open.*\+|ioutil\.ReadFile.*\+`

**Reference(s):** CVE-2025-9079, CVE-2025-22873, OWASP Path Traversal Guide[11][12][13][15]

***

## LDAP Injection

**Bad Pattern 1: String concatenation in LDAP filters**
```go
searchRequest := "(&(objectClass=organizationalPerson)(uid=" + username + "))"
sr, err := l.Search(ldap.NewSearchRequest(..., searchRequest, ...))
```
Explanation: Direct string concatenation in LDAP queries allows injection of LDAP operators to bypass authentication or access unauthorized data[16][17][18].

**Bad Pattern 2: Unescaped user input in LDAP search**
```go
filter := fmt.Sprintf("(cn=%s)", userInput)
result := ldapConn.Search(filter)
```
Explanation: Unescaped user input in LDAP filters enables attackers to manipulate queries using special LDAP characters[16][17][19].

**Bad Pattern 3: Direct parameter injection**
```go
bindDN := "uid=" + username + ",ou=users,dc=example,dc=com"
err := conn.Bind(bindDN, password)
```
Explanation: User-controlled distinguished names in LDAP bind operations can lead to authentication bypass[16][18][19].

**Regex (starter pattern):** `ldap\.NewSearchRequest.*\+|fmt\.Sprintf.*$$cn=|uid=.*\+`

**Reference(s):** Fluid Attacks LDAP Injection, BrightSec LDAP Injection Guide, Trend Micro LDAP Prevention[16][17][18][19]

***

## Server-Side Template Injection (SSTI)

**Bad Pattern 1: Direct user input in template parsing**
```go
tmpl, err := template.New("search").Parse(fmt.Sprintf(`<h2>Results for query "%s":</h2>`, query))
```
Explanation: User input directly inserted into template strings enables template injection attacks that can lead to remote code execution[20][21][22].

**Bad Pattern 2: Template execution with unvalidated data**
```go
t := template.Must(template.New("page").Parse(userTemplate))
t.Execute(w, data)
```
Explanation: Executing templates with user-controlled content allows attackers to access server-side objects and execute arbitrary code[20][22][23].

**Bad Pattern 3: Html template with dangerous functions**
```go
tmpl := template.New("custom").Funcs(template.FuncMap{"dangerous": dangerousFunction})
tmpl.Parse(userInput)
```
Explanation: Custom template functions that execute system commands or access sensitive data create RCE vulnerabilities when combined with user input[21][23].

**Regex (starter pattern):** `template\.New.*Parse.*fmt\.Sprintf|template\.Must.*userTemplate|FuncMap.*dangerous`

**Reference(s):** Payatu SSTI in Golang, Snyk SSTI Guide, OnSecurity Go SSTI Research[20][21][22][23]

***

## XML External Entity (XXE)

**Bad Pattern 1: Unvalidated XML parsing with encoding/xml**
```go
decoder := xml.NewDecoder(req.Body)
var data MyStruct
decoder.Decode(&data)
```
Explanation: Go's encoding/xml package is naturally protected against XXE, but using third-party XML libraries without proper configuration can introduce vulnerabilities[24][25][26].

**Bad Pattern 2: Custom XML parser without entity restrictions**
```go
// Using libxml2 bindings or similar
parser := libxml.NewParser()
parser.ParseString(userXML) // Potentially vulnerable
```
Explanation: Third-party XML parsers may enable external entity processing, leading to file disclosure or SSRF attacks[24][26][27].

**Bad Pattern 3: XML processing with external entity enablement**
```go
// Hypothetical vulnerable XML processing
config := xmlparser.Config{EnableExternalEntities: true}
result := xmlparser.Parse(userInput, config)
```
Explanation: Explicitly enabling external entity processing in XML parsers creates XXE vulnerabilities[25][26][27].

**Regex (starter pattern):** `xml\.NewDecoder.*req\.Body|libxml.*ParseString|EnableExternalEntities.*true`

**Reference(s):** StackHawk XXE Prevention, HackWithPassion XXE in Go, Cobalt XXE Guide[24][25][26][27]

***

## Insecure Deserialization

**Bad Pattern 1: Unvalidated JSON deserialization**
```go
var user User
err := json.NewDecoder(c.Request.Body).Decode(&user)
// No validation after decoding
```
Explanation: Deserializing untrusted data without validation can lead to unexpected application behavior or security issues[28][29][30].

**Bad Pattern 2: Gob deserialization without type safety**
```go
decoder := gob.NewDecoder(conn)
var data interface{}
decoder.Decode(&data)
```
Explanation: Go's gob package requires careful handling to prevent deserialization of unexpected types that could cause panics or security issues[28][31][32].

**Bad Pattern 3: Custom deserialization without validation**
```go
func deserialize(data []byte) interface{} {
    var result interface{}
    json.Unmarshal(data, &result)
    return result // No type checking
}
```
Explanation: Generic deserialization without type validation can lead to type confusion attacks or application crashes[28][30][33].

**Regex (starter pattern):** `json\.NewDecoder.*\.Decode|gob\.NewDecoder.*interface|Unmarshal.*interface`

**Reference(s):** Fluid Attacks Insecure Deserialization, Let's Do Tech Serialization Guide[28][29][30]

***

## Race Conditions

**Bad Pattern 1: Unsynchronized shared variable access**
```go
var counter int = 0
func increment() {
    for i := 0; i < 10000; i++ {
        counter++ // Race condition
    }
}
```
Explanation: Concurrent access to shared variables without synchronization can lead to data corruption and unpredictable behavior[34][35][36].

**Bad Pattern 2: TOCTTOU (Time of Check Time of Use)**
```go
if fileExists(filename) {
    // Race condition window
    content := readFile(filename) // File might be deleted/modified
}
```
Explanation: Checking and using resources in separate operations creates race condition vulnerabilities that can be exploited for privilege escalation[34][35][37].

**Bad Pattern 3: Unprotected map operations**
```go
var sharedMap = make(map[string]int)
func updateMap(key string, value int) {
    sharedMap[key] = value // Concurrent map writes panic
}
```
Explanation: Concurrent map operations without synchronization cause runtime panics and potential data corruption[34][36][37].

**Regex (starter pattern):** `var.*int.*=.*0|fileExists.*readFile|make$$map.*$$.*$$`

**Reference(s):** YesWeHack Race Conditions, CheckMarx Race Conditions, AntonZ Go Concurrency[34][35][36][37]

***

## Unsafe Memory Operations

**Bad Pattern 1: Arbitrary pointer arithmetic**
```go
arr := [3]int{1, 2, 3}
ptr := unsafe.Pointer(&arr)
value := *(*int)(unsafe.Add(ptr, 5 * unsafe.Sizeof(arr[0]))) // Out of bounds
```
Explanation: Unsafe pointer arithmetic can cause buffer overflows, memory corruption, and security vulnerabilities[38][39][40][41].

**Bad Pattern 2: Type casting with unsafe.Pointer**
```go
var x int = 42
p := (*string)(unsafe.Pointer(&x)) // Invalid type conversion
fmt.Println(*p) // Undefined behavior
```
Explanation: Incorrect type casting using unsafe pointers can lead to memory corruption and unpredictable program behavior[38][42][43].

**Bad Pattern 3: Dangling pointer access**
```go
func getDanglingPointer() unsafe.Pointer {
    x := 42
    return unsafe.Pointer(&x) // x goes out of scope
}
ptr := getDanglingPointer()
value := *(*int)(ptr) // Accessing freed memory
```
Explanation: Accessing memory through unsafe pointers after the original variable is out of scope causes undefined behavior and security issues[38][39][41].

**Regex (starter pattern):** `unsafe\.Add.*\*.*unsafe\.Sizeof|\*$$\*.*$$.*unsafe\.Pointer|unsafe\.Pointer.*&`

**Reference(s):** SecureGo G103 Rule, Go Geiger Study, Unsafe Pointer Usage Guide[38][39][40][41]

***

## TLS/Certificate Validation Bypass

**Bad Pattern 1: InsecureSkipVerify enabled**
```go
tr := &http.Transport{
    TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
}
client := &http.Client{Transport: tr}
```
Explanation: Disabling TLS certificate verification enables man-in-the-middle attacks and compromises secure communications[4][44][45].

**Bad Pattern 2: Custom certificate verification bypass**
```go
config := &tls.Config{
    VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
        return nil // Always accept certificates
    },
}
```
Explanation: Custom certificate verification that always returns nil bypasses all certificate validation and enables impersonation attacks[4][45][46].

**Bad Pattern 3: Ignoring certificate errors**
```go
conn, err := tls.Dial("tcp", address, &tls.Config{})
if err != nil {
    // Ignore certificate errors and continue
    conn, _ = tls.Dial("tcp", address, &tls.Config{InsecureSkipVerify: true})
}
```
Explanation: Falling back to insecure connections when certificate validation fails defeats the purpose of TLS security[4][47][48].

**Regex (starter pattern):** `InsecureSkipVerify.*true|VerifyPeerCertificate.*return.*nil|tls\.Config.*InsecureSkipVerify`

**Reference(s):** CyberArk SSL Bypass, CVE-2018-16875, Go TLS Documentation[4][44][45][47]

***

## HTTP Response Splitting/Header Injection

**Bad Pattern 1: Direct user input in HTTP headers**
```go
userValue := req.FormValue("redirect")
w.Header().Set("Location", userValue)
```
Explanation: Unvalidated user input in HTTP headers can lead to response splitting attacks and cache poisoning[49][50][51].

**Bad Pattern 2: Cookie injection with user data**
```go
cookie := &http.Cookie{
    Name:  "session",
    Value: req.FormValue("sessiondata"), // User controlled
}
http.SetCookie(w, cookie)
```
Explanation: User-controlled cookie values can inject additional headers or split HTTP responses to perform XSS or cache poisoning attacks[50][51][52].

**Bad Pattern 3: Header manipulation**
```go
customHeader := fmt.Sprintf("Bearer %s\r\nX-Injected: malicious", userToken)
req.Header.Set("Authorization", customHeader)
```
Explanation: Including CRLF sequences in header values enables header injection and HTTP response splitting attacks[51][53][54].

**Regex (starter pattern):** `Header$$$$\.Set.*FormValue|http\.Cookie.*FormValue|fmt\.Sprintf.*\\r\\n`

**Reference(s):** PortSwigger HTTP Response Header Injection, CWE-113, Detectify Response Splitting[49][50][51][53][52]

This research provides concrete patterns of vulnerable code in Go applications, focusing on server-side vulnerabilities that can lead to remote code execution, data breaches, and system compromise. Each pattern includes specific Go functions and methods that, when misused, create security vulnerabilities.

Sources
- [1] Golang SQL Injection By Example https://snyk.io/articles/golang-sql-injection-by-example/
- [2] Golang SQL Injection Guide: Examples and Prevention https://www.stackhawk.com/blog/golang-sql-injection-guide-examples-and-prevention/
- [3] SQL Injection Vulnerability in GoLang Code #2 | by Aswin KV https://infosecwriteups.com/sql-injection-vulnerability-in-golang-code-2-3536f027516d
- [4] How to Bypass Golang SSL Verification https://www.cyberark.com/resources/threat-research-blog/how-to-bypass-golang-ssl-verification
- [5] How to avoid SSRF vulnerability in Go applications https://snyk.io/articles/how-to-avoid-ssrf-vulnerability-in-go-applications/
- [6] Server-side request forgery (SSRF) - Go - Knowledge Base https://help.fluidattacks.com/portal/en/kb/articles/criteria-fixes-go-100
- [7] Server-side Request Forgery (SSRF) in golang.org/x/net ... https://security.snyk.io/vuln/SNYK-GOLANG-GOLANGORGXNETHTTPHTTPPROXY-9058601
- [8] Command injection prevention for Go https://semgrep.dev/docs/cheat-sheets/go-command-injection
- [9] Golang Command Injection: Examples and Prevention https://www.stackhawk.com/blog/golang-command-injection-examples-and-prevention/
- [10] Understanding command injection vulnerabilities in Go https://snyk.io/blog/understanding-go-command-injection-vulnerabilities/
- [11] AXRoux/Ghost-Path-Traversal-CVE-2023-32235 https://github.com/AXRoux/Ghost-Path-Traversal-CVE-2023-32235-
- [12] Path Traversal https://owasp.org/www-community/attacks/Path_Traversal
- [13] CVE-2025-9079: Mattermost Path Traversal vulnerability https://www.miggo.io/vulnerability-database/cve/CVE-2025-9079
- [14] CVE-2024-13059: Exploiting Path Traversal in ... https://www.offsec.com/blog/cve-2024-13059/
- [15] Golang 1.24.x < 1.24.3 Directory Traversal https://www.tenable.com/plugins/nessus/235470
- [16] LDAP injection - Go - Knowledge Base https://help.fluidattacks.com/portal/en/kb/articles/criteria-fixes-go-107
- [17] A Pentester Guide to LDAP Bind Method Vulnerabilities https://www.cobalt.io/blog/pentester-guide-ldap-bind-method-vulnerabilities
- [18] LDAP Injection Guide: Types, Examples, Prevention https://brightsec.com/blog/ldap-injection/
- [19] How to Avoid LDAP Injection Attacks https://www.trendmicro.com/en_my/research/23/c/avoid-ldap-injection-attacks.html
- [20] Exploring ways to exploit SSTI in Golang Frameworks https://payatu.com/blog/ssti-in-golang/
- [21] Understanding Server-Side Template Injection in Golang https://snyk.io/articles/understanding-server-side-template-injection-in-golang/
- [22] Server-Side Template Injection Guide and Prevention Tips https://abnormal.ai/blog/server-side-template-injection
- [23] What Is Server-Side Templating and SSTI in Golang? https://www.oligo.security/blog/safe-by-default-or-vulnerable-by-design-golang-server-side-template-injection
- [24] Preventing XML External Entities in Golang https://www.stackhawk.com/blog/golang-xml-external-entities-guide-examples-and-prevention/
- [25] How to Execute an XML External Entity Injection (XXE) https://www.cobalt.io/blog/how-to-execute-an-xml-external-entity-injection-xxe
- [26] XXEs in Golang are surprisingly hard - hack.with(passion) https://www.hackwithpassion.com/xxes-in-golang-are-surprisingly-hard/
- [27] Preventing XML External Entity Attacks - Trailhead https://trailhead.salesforce.com/content/learn/modules/security-principles/prevent-extensible-markup-language-external-entity-attacks
- [28] Insecure deserialization - Go - Knowledge Base https://help.fluidattacks.com/portal/en/kb/articles/criteria-fixes-go-096
- [29] Data Serialization and Deserialization in Go 🔁 - Let's Do Tech https://news.letsdote.ch/p/data-serialization-and-deserialization
- [30] Deserialization vulnerabilities: attacking deserialization in JS https://www.acunetix.com/blog/web-security-zone/deserialization-vulnerabilities-attacking-deserialization-in-js/
- [31] Golang GOB deserialization issue https://stackoverflow.com/questions/79081387/golang-gob-deserialization-issue
- [32] Go deserialization when type is not known https://stackoverflow.com/questions/59062330/go-deserialization-when-type-is-not-known
- [33] Jake-Schoellkopf/Insecure-Java-Deserialization https://github.com/Jake-Schoellkopf/Insecure-Java-Deserialization
- [34] Ultimate Bug Bounty guide to race condition vulnerabilities https://www.yeswehack.com/learn-bug-bounty/ultimate-guide-race-condition-vulnerabilities
- [35] Race Conditions Can Exist in Go https://checkmarx.com/blog/race-conditions-can-exist-in-go/
- [36] Understanding and Resolving Race Conditions in Golang ... https://thinhdanggroup.github.io/golang-race-conditions/
- [37] Gist of Go: Race conditions https://antonz.org/go-concurrency/race-conditions/
- [38] Working with Unsafe Package in Go https://golang.howtos.io/working-with-unsafe-package-in-go/
- [39] G103: Use of unsafe block - Secure Go https://securego.io/docs/rules/g103
- [40] Uncovering the Hidden Dangers: Finding Unsafe Go Code ... https://arxiv.org/abs/2010.11242
- [41] Unsafe Package Usage in Go - Go Cookbook https://go-cookbook.com/snippets/standard-library-packages/unsafe-package
- [42] Unsafe Pointers in Go, Should I Ever I Bothered About It https://blog.devgenius.io/unsafe-pointers-in-go-should-i-ever-i-bothered-about-it-9d1d9db1a97c
- [43] Risks and benefits of Go's unsafe pointers https://app.studyraid.com/en/read/15259/528864/risks-and-benefits-of-gos-unsafe-pointers
- [44] crypto/tls: feature request: add option to JUST skip ... https://github.com/golang/go/issues/21971
- [45] TLS certificate validation in Golang: CRL & OCSP examples https://www.cossacklabs.com/blog/tls-validation-implementing-ocsp-and-crl-in-go/
- [46] does tls.Config.VerifyPeerCertificate bypass the default ... https://stackoverflow.com/questions/77224489/does-tls-config-verifypeercertificate-bypass-the-default-provided-checks-in-gola
- [47] Understanding Golang TLS mutual authentication DoS https://apisecurity.io/mutual-tls-authentication-vulnerability-in-go-cve-2018-16875/
- [48] How to Bypass Golang SSL Verification : r/netsec https://www.reddit.com/r/netsec/comments/1e52yj1/how_to_bypass_golang_ssl_verification/
- [49] HTTP response splitting — CodeQL query help documentation https://codeql.github.com/codeql-query-help/java/java-http-response-splitting/
- [50] HTTP response header injection https://portswigger.net/kb/issues/00200200_http-response-header-injection
- [51] HTTP Response Splitting https://owasp.org/www-community/attacks/HTTP_Response_Splitting
- [52] CWE-113: Improper Neutralization of CRLF Sequences ... - Mitre https://cwe.mitre.org/data/definitions/113.html
- [53] HTTP response splitting exploitations & mitigations https://blog.detectify.com/industry-insights/http-response-splitting-exploitations-and-mitigations/
- [54] What is CRLF Injection | Types & Prevention Techniques https://www.imperva.com/learn/application-security/crlf-injection/
