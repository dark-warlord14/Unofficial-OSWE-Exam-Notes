# Deep Research — Server-Side Vulnerabilities & Dangerous Code Patterns in C++

## Buffer Overflow Vulnerabilities

**Bad Pattern 1: `strcpy()` without bounds checking**
```cpp
char buffer[10];
strcpy(buffer, user_input); // Unbounded copy
```
**Explanation:** Copies data without checking destination buffer size, allowing overflow and potential code execution.[1][2][3]

**Bad Pattern 2: `sprintf()` with user-controlled format string**
```cpp
char buffer[256];
sprintf(buffer, user_input); // Format string vulnerability
```
**Explanation:** Unbounded formatting can overflow buffer and allow arbitrary memory writes.[2][4][5]

**Bad Pattern 3: `strcat()` without length validation**
```cpp
char dest[100] = "Hello ";
strcat(dest, user_input); // No bounds checking
```
**Explanation:** Concatenates without verifying total length fits in destination buffer.[2][3]

**Regex (starter pattern):** `\b(strcpy|strcat|sprintf|gets)\s*$$`

**Reference(s):** CVE database buffer overflow entries, OWASP Buffer Overflow Attack documentation[3]

## Command Injection Vulnerabilities

**Bad Pattern 1: `system()` with user input**
```cpp
std::string cmd = "cat " + user_filename;
system(cmd.c_str()); // Direct command execution
```
**Explanation:** Executes shell commands with unsanitized user input, enabling arbitrary command execution.[6][7]

**Bad Pattern 2: `popen()` with concatenated user data**
```cpp
std::string command = "grep pattern " + user_file;
FILE* pipe = popen(command.c_str(), "r");
```
**Explanation:** Opens process pipe with user-controlled command, allowing command injection attacks.[8]

**Bad Pattern 3: `exec()` family functions with user input**
```cpp
execl("/bin/sh", "sh", "-c", user_command, NULL);
```
**Explanation:** Directly executes user-provided commands without validation or sanitization.[6]

**Regex (starter pattern):** `\b(system|popen|exec[a-z]*)\s*$$`

**Reference(s):** OWASP Command Injection documentation[9], Infosec Institute Command Injection guide[6]

## Path Traversal Vulnerabilities

**Bad Pattern 1: Direct file path concatenation**
```cpp
std::string filepath = "/var/www/uploads/" + user_filename;
std::ifstream file(filepath);
```
**Explanation:** Concatenates user input to file paths without sanitizing "../" sequences, enabling directory traversal.[10][11][12]

**Bad Pattern 2: `fopen()` with user-controlled paths**
```cpp
FILE* file = fopen(user_path.c_str(), "r");
```
**Explanation:** Opens files using unsanitized user paths, allowing access to unauthorized files.[10][13]

**Bad Pattern 3: File operations with relative paths**
```cpp
std::filesystem::path target = base_dir / user_input;
std::ofstream outfile(target);
```
**Explanation:** File system operations without normalizing or validating path components.[10][12]

**Regex (starter pattern):** `\b(fopen|ifstream|ofstream|std::filesystem::path)\s*$$`

**Reference(s):** Snyk directory traversal research[10], OWASP Path Traversal documentation[12]

## SQL Injection Vulnerabilities

**Bad Pattern 1: String concatenation in SQL queries**
```cpp
std::string query = "SELECT * FROM users WHERE username='" + user_name + "'";
// Execute query
```
**Explanation:** Builds SQL queries by string concatenation, allowing injection of malicious SQL code.[14][15]

**Bad Pattern 2: Direct parameter insertion without prepared statements**
```cpp
sprintf(sql_buffer, "INSERT INTO table VALUES ('%s', %d)", user_data, user_id);
```
**Explanation:** Formats SQL with user data without parameterization, enabling SQL injection attacks.[14][16]

**Bad Pattern 3: Dynamic query construction**
```cpp
std::string where_clause = " WHERE id = " + user_id;
std::string query = "DELETE FROM users" + where_clause;
```
**Explanation:** Dynamically builds queries with user input without proper escaping or validation.[15][17]

**Regex (starter pattern):** `(SELECT|INSERT|UPDATE|DELETE).*\+.*user|sprintf.*SELECT|sprintf.*INSERT`

**Reference(s):** BrightSec SQL Injection examples[14], PortSwigger SQL Injection guide[15]

## Format String Vulnerabilities

**Bad Pattern 1: `printf()` with user-controlled format string**
```cpp
printf(user_input); // Direct user input as format
```
**Explanation:** Uses user input as format string, enabling memory read/write through format specifiers.[18][19][20]

**Bad Pattern 2: `syslog()` with unsanitized user data**
```cpp
syslog(LOG_INFO, user_message);
```
**Explanation:** Logs user input as format string, allowing information disclosure and memory corruption.[5][21]

**Bad Pattern 3: `fprintf()` with user-controlled format**
```cpp
fprintf(logfile, user_log_entry);
```
**Explanation:** Writes user input as format string to file, enabling format string exploitation.[19][22]

**Regex (starter pattern):** `\b(printf|fprintf|sprintf|syslog)\s*$$\s*[a-zA-Z_][a-zA-Z0-9_]*\s*$$`

**Reference(s):** CTF101 Format String Vulnerability guide[18], GeeksforGeeks Format String documentation[19]

## XML External Entity (XXE) Vulnerabilities

**Bad Pattern 1: libxml2 parser with external entities enabled**
```cpp
xmlDocPtr doc = xmlParseMemory(xml_data, size);
// Default parser allows external entities
```
**Explanation:** Uses default XML parser configuration that processes external entities, enabling file disclosure.[23][24][25]

**Bad Pattern 2: Xerces-C++ parser without security features**
```cpp
XercesDOMParser parser;
parser.parse(user_xml_file); // Default settings vulnerable
```
**Explanation:** Default XML parser settings allow external entity processing, leading to XXE attacks.[26][24]

**Bad Pattern 3: Custom XML parsing without entity validation**
```cpp
// Parse XML without disabling external entities
xmlSetExternalEntityLoader(NULL); // Still vulnerable
xmlDocPtr doc = xmlReadMemory(xml_buffer, size, NULL, NULL, 0);
```
**Explanation:** XML parsing without explicitly disabling external entity processing.[27][24]

**Regex (starter pattern):** `\b(xmlParseMemory|xmlReadMemory|XercesDOMParser)\s*$$`

**Reference(s):** OWASP XXE Prevention Cheat Sheet[24], SonarSource XXE vulnerability analysis[25]

## Use-After-Free Vulnerabilities

**Bad Pattern 1: Accessing freed memory**
```cpp
int* ptr = (int*)malloc(sizeof(int));
free(ptr);
*ptr = 42; // Use after free
```
**Explanation:** Continues using memory pointer after deallocation, causing undefined behavior and potential exploitation.[28][29][30]

**Bad Pattern 2: Double free with continued access**
```cpp
delete obj;
// ... later in code
obj->method(); // Use after free
```
**Explanation:** Accesses object methods after deletion, leading to use-after-free condition.[29][31]

**Bad Pattern 3: Stale pointer usage in containers**
```cpp
std::vector<Object*> vec;
delete vec[0];
vec[0]->process(); // Use after free
```
**Explanation:** Uses deleted object pointer still stored in container without removal.[28][32]

**Regex (starter pattern):** `\b(free|delete)\s*$$[^;]+;.*\*.*=|->)`

**Reference(s):** CQR Use-After-Free vulnerability guide[28], Snyk UAF tutorial[29]

## Insecure Deserialization Vulnerabilities

**Bad Pattern 1: Boost serialization without validation**
```cpp
std::ifstream ifs(user_file);
boost::archive::binary_iarchive ia(ifs);
ia >> my_object; // Deserialize without validation
```
**Explanation:** Deserializes untrusted data without integrity checks, enabling object manipulation attacks.[33][34]

**Bad Pattern 2: Custom deserialization of user data**
```cpp
void deserialize(char* buffer) {
    memcpy(&sensitive_object, buffer, sizeof(sensitive_object));
}
```
**Explanation:** Direct memory copying of user data into objects without validation or type checking.[35][36]

**Bad Pattern 3: JSON deserialization without schema validation**
```cpp
// Using RapidJSON or similar
Document d;
d.Parse(user_json_string); // No schema validation
```
**Explanation:** Parses JSON from untrusted sources without validating structure or content.[34][37]

**Regex (starter pattern):** `\b(boost::archive|memcpy.*sizeof|Parse.*user)\s*$$`

**Reference(s):** Reddit C++ deserialization security discussion[34], OWASP Insecure Deserialization[37]

## Server-Side Request Forgery (SSRF) Vulnerabilities

**Bad Pattern 1: libcurl with user-controlled URLs**
```cpp
CURL *curl = curl_easy_init();
curl_easy_setopt(curl, CURLOPT_URL, user_url.c_str());
curl_easy_perform(curl); // SSRF vulnerability
```
**Explanation:** Makes HTTP requests to user-specified URLs without validation, enabling SSRF attacks.[38][39][40]

**Bad Pattern 2: Boost.Asio HTTP client with user URLs**
```cpp
boost::asio::ip::tcp::resolver resolver(io_context);
auto endpoints = resolver.resolve(user_host, user_port);
// Connect without validation
```
**Explanation:** Resolves and connects to user-provided hosts without restriction, allowing internal network access.[41][42]

**Bad Pattern 3: HTTP client libraries with URL concatenation**
```cpp
std::string api_url = "http://internal-api/" + user_endpoint;
// Make request to constructed URL
```
**Explanation:** Builds URLs by concatenating user input without validation, enabling SSRF through path manipulation.[43][39]

**Regex (starter pattern):** `\b(curl_easy_setopt.*CURLOPT_URL|resolver\.resolve)\s*$$`

**Reference(s):** Acunetix SSRF vulnerability guide[41], Invicti SSRF explanation[39]

## File Upload Vulnerabilities

**Bad Pattern 1: Direct file writing without path validation**
```cpp
std::string filepath = upload_dir + "/" + uploaded_filename;
std::ofstream file(filepath, std::ios::binary);
// Write file content without validation
```
**Explanation:** Writes uploaded files to paths constructed from user input without sanitization, enabling path traversal.[44][45]

**Bad Pattern 2: Multipart form parsing without filename checks**
```cpp
// Parse multipart data
std::string filename = get_filename_from_multipart(request);
save_file(upload_path + filename, file_data);
```
**Explanation:** Extracts and uses filenames from multipart uploads without validating or sanitizing paths.[46][47]

**Bad Pattern 3: File type validation by extension only**
```cpp
if (filename.ends_with(".jpg") || filename.ends_with(".png")) {
    save_uploaded_file(filename, data); // Insufficient validation
}
```
**Explanation:** Relies solely on file extensions for type validation, easily bypassed by attackers.[45][46]

**Regex (starter pattern):** `\b(ofstream|save.*file.*upload|multipart.*filename)\s*$$`

**Reference(s):** Cortex.cpp vulnerability analysis[44], Intigriti file upload exploitation guide[45]

This comprehensive analysis covers the major server-side vulnerability classes in C++, providing concrete examples of dangerous code patterns, their security implications, and practical regex patterns for detection. Each vulnerability class includes real-world examples and references to authoritative security sources and CVE databases.

Sources
- [1] how shall we use `strcpy`, `strcat`, and `sprintf` securely? ... https://www.reddit.com/r/C_Programming/comments/jh9fsz/how_shall_we_use_strcpy_strcat_and_sprintf/
- [2] Buffer Overflow https://www.invicti.com/learn/buffer-overflow-stack-overflow-heap-overflow/
- [3] Buffer Overflow Attack https://owasp.org/www-community/attacks/Buffer_overflow_attack
- [4] sprintf function's buffer overflow? https://stackoverflow.com/questions/4282281/sprintf-functions-buffer-overflow
- [5] Uncontrolled format string - Vulnerabilities https://www.acunetix.com/vulnerabilities/web/uncontrolled-format-string/
- [6] Command Injection Vulnerabilities https://www.infosecinstitute.com/resources/secure-coding/command-injection-vulnerabilities/
- [7] What is OS command injection, and how to prevent it? https://portswigger.net/web-security/os-command-injection
- [8] How to Protect C Code from Buffer Overflow Attacks https://moldstud.com/articles/p-ultimate-guide-to-protecting-your-c-code-from-buffer-overflow-attacks
- [9] Command Injection https://owasp.org/www-community/attacks/Command_Injection
- [10] Exploring 3 types of directory traversal vulnerabilities in C/ ... https://snyk.io/blog/exploring-3-types-of-directory-traversal-vulnerabilities-in-c-c/
- [11] What is path traversal, and how to prevent it? https://portswigger.net/web-security/file-path-traversal
- [12] Path Traversal https://owasp.org/www-community/attacks/Path_Traversal
- [13] Directory Traversal (Path Traversal) https://www.invicti.com/learn/directory-traversal-path-traversal/
- [14] SQL Injection Attack: How It Works, Examples and Prevention https://brightsec.com/blog/sql-injection-attack/
- [15] What is SQL Injection? Tutorial & Examples | Web Security ... https://portswigger.net/web-security/sql-injection
- [16] SQL Injection Prevention - OWASP Cheat Sheet Series https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html
- [17] SQL Injection - SQL Server https://learn.microsoft.com/en-us/sql/relational-databases/security/sql-injection?view=sql-server-ver17
- [18] Format String Vulnerability https://ctf101.org/binary-exploitation/what-is-a-format-string-vulnerability/
- [19] Format String Vulnerability and Prevention with Example https://www.geeksforgeeks.org/c/format-string-vulnerability-and-prevention-with-example/
- [20] Testing for Format String Injection https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/13-Testing_for_Format_String_Injection
- [21] What Are Format String Vulnerabilities? https://www.invicti.com/blog/web-security/format-string-vulnerabilities/
- [22] Format string attack https://owasp.org/www-community/attacks/Format_string_attack
- [23] XML External Entity https://www.geeksforgeeks.org/ethical-hacking/xml-external-entity-xxe-processing/
- [24] XML External Entity Prevention - OWASP Cheat Sheet Series https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html
- [25] C++ static code analysis | Vulnerability https://rules.sonarsource.com/cpp/type/vulnerability/rspec-2755/
- [26] Apache Xerces-c++ security vulnerabilities, ... https://www.cvedetails.com/product/4103/Apache-Xerces-c-.html?vendor_id=45
- [27] XML External Entity (XXE) https://www.invicti.com/learn/xml-external-entity-xxe/
- [28] Use-After-Free vulnerability https://cqr.company/web-vulnerabilities/use-after-free-vulnerability/
- [29] Use after free vulnerability | Tutorial & Examples https://learn.snyk.io/lesson/use-after-free/
- [30] Using freed memory https://owasp.org/www-community/vulnerabilities/Using_freed_memory
- [31] Top Six Most Dangerous Vulnerabilities in C and C++ https://www.code-intelligence.com/blog/most-dangerous-vulnerabilities-cwes-in-c-2025
- [32] CWE-416 Vulnerability Overview, How to Fix & Prevent It https://www.backslash.security/blog/cwe-416
- [33] Insecure Deserialization https://spyboy.blog/2023/05/26/insecure-deserialization/
- [34] Secure serialization and deserialization in C++ : r/cpp https://www.reddit.com/r/cpp/comments/xxtclw/secure_serialization_and_deserialization_in_c/
- [35] Insecure Deserialization | Tutorials & Examples https://learn.snyk.io/lesson/insecure-deserialization/
- [36] Insecure deserialization | Web Security Academy https://portswigger.net/web-security/deserialization
- [37] Insecure Deserialization https://owasp.org/www-community/vulnerabilities/Insecure_Deserialization
- [38] Server-Side Request Forgery (SSRF) https://github.com/paulveillard/cybersecurity-ssrf
- [39] Server-Side Request Forgery (SSRF) https://www.invicti.com/learn/server-side-request-forgery-ssrf/
- [40] Security Bulletin: Multiple vulnerabilities in IBM WebSphere ... https://www.ibm.com/support/pages/node/7157929
- [41] What is server-side request forgery (SSRF)? https://www.acunetix.com/blog/articles/server-side-request-forgery-vulnerability/
- [42] What is SSRF (Server-side request forgery)? Tutorial & ... https://portswigger.net/web-security/ssrf
- [43] Identifying Server Side Request Forgery https://www.tenable.com/blog/identifying-server-side-request-forgery-how-tenable-io-web-application-scanning-can-help
- [44] Exploring Vulnerabilities in Cortex.cpp, Jan's AI Engine https://labs.snyk.io/resources/in-localhost-we-trust-exploring-vulnerabilities-in-cortex-cpp-jans-ai-engine/
- [45] File Upload Vulnerabilities: Advanced Exploitation Guide https://www.intigriti.com/researchers/blog/hacking-tools/insecure-file-uploads-a-complete-guide-to-finding-advanced-file-upload-vulnerabilities
- [46] Understanding File Upload Vulnerabilities https://aardwolfsecurity.com/understanding-file-upload-vulnerabilities/
- [47] File uploads | Web Security Academy https://portswigger.net/web-security/file-upload
