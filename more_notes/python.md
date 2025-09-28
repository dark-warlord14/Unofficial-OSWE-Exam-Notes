# Deep Research — Server-Side Vulnerabilities & Dangerous Code Patterns in Python

## Remote Code Execution (RCE)

**Bad Pattern 1:** `eval()` with user input
```python
user_input = request.GET.get('expr')
result = eval(user_input)  # Executes arbitrary Python code
```
**Explanation:** `eval()` executes any valid Python expression, allowing attackers to run arbitrary code when user input is not sanitized.[1][2]

**Bad Pattern 2:** `exec()` with dynamic content
```python
command = f"print('{user_data}')"
exec(command)  # Executes arbitrary Python statements
```
**Explanation:** `exec()` can execute any Python code, making it dangerous when processing user-controlled input.[3][2]

**Bad Pattern 3:** `pickle.loads()` on untrusted data
```python
import pickle
data = request.POST.get('payload')
obj = pickle.loads(base64.b64decode(data))  # Deserializes malicious objects
```
**Explanation:** Pickle deserialization can execute arbitrary code through crafted payloads using `__reduce__` methods.[4][5][6]

**Regex (starter pattern):** `\b(eval|exec|pickle\.loads?)\s*$$`

**Reference(s):** CVE-2022-29216, CVE-2025-3248, OWASP Code Injection[1][7][2]

## SQL Injection

**Bad Pattern 1:** String formatting in database queries
```python
cursor.execute("SELECT * FROM users WHERE id = '%s'" % user_id)
```
**Explanation:** Direct string interpolation allows SQL injection through malicious input crafted to manipulate query structure.[8][9]

**Bad Pattern 2:** `.format()` method in SQL queries
```python
query = "SELECT * FROM users WHERE name = '{}'".format(username)
cursor.execute(query)
```
**Explanation:** String formatting methods don't escape SQL special characters, enabling injection attacks.[8][10]

**Bad Pattern 3:** f-string concatenation in queries
```python
sql = f"DELETE FROM users WHERE id = {user_input}"
cursor.execute(sql)
```
**Explanation:** F-strings directly embed user input without sanitization, allowing SQL manipulation.[11][10]

**Regex (starter pattern):** `\.execute\s*$$\s*["\'].*%s.*["\']|\.execute\s*$$\s*f["\']|\.format$$`

**Reference(s):** CVE-2024-9774, OWASP SQL Injection Prevention[12][8][10]

## Server-Side Request Forgery (SSRF)

**Bad Pattern 1:** `urllib.request.urlopen()` with user-controlled URLs
```python
import urllib.request
url = request.GET.get('url')
response = urllib.request.urlopen(url)  # Fetches arbitrary URLs
```
**Explanation:** Allows attackers to make requests to internal services or external systems via the server.[13][14]

**Bad Pattern 2:** `requests.get()` without URL validation
```python
import requests
target = user_input
response = requests.get(target)  # No validation of target URL
```
**Explanation:** Enables access to internal networks, cloud metadata endpoints, and other restricted resources.[13][15]

**Bad Pattern 3:** `http.client.HTTPConnection()` with user input
```python
import http.client
conn = http.client.HTTPConnection(user_host)
conn.request("GET", user_path)
```
**Explanation:** Direct HTTP connections using user input can target internal services bypassing firewalls.[14][16]

**Regex (starter pattern):** `(urllib\.request\.urlopen|requests\.(get|post)|HTTPConnection)\s*$$`

**Reference(s):** OWASP A10:2021 SSRF, PortSwigger SSRF Guide[13][14][17]

## Command Injection

**Bad Pattern 1:** `os.system()` with user input
```python
import os
filename = request.GET.get('file')
os.system(f"cat {filename}")  # Executes shell commands
```
**Explanation:** `os.system()` executes arbitrary shell commands, allowing command injection through user input.[18][19]

**Bad Pattern 2:** `subprocess.run()` with `shell=True`
```python
import subprocess
cmd = request.form['command']
subprocess.run(cmd, shell=True)  # Shell interprets command
```
**Explanation:** Using `shell=True` enables command chaining and injection through shell metacharacters.[18][20]

**Bad Pattern 3:** `subprocess.Popen()` with unsanitized input
```python
import subprocess
process = subprocess.Popen(user_command, shell=True)
```
**Explanation:** `Popen` with shell execution allows attackers to inject additional commands via separators.[18][21]

**Regex (starter pattern):** `(os\.system|subprocess\.(run|call|Popen))\s*$$.*shell\s*=\s*True`

**Reference(s):** CVE-2023-6507, Snyk Command Injection Guide[18][22][19]

## Path Traversal

**Bad Pattern 1:** `open()` with unsanitized file paths
```python
filename = request.GET.get('file')
with open(f"/uploads/{filename}", 'r') as f:  # No path validation
    content = f.read()
```
**Explanation:** Direct concatenation of user input allows directory traversal using `../` sequences.[23][24]

**Bad Pattern 2:** `tarfile.extractall()` without validation
```python
import tarfile
tar = tarfile.open(uploaded_file)
tar.extractall()  # Extracts to arbitrary paths
```
**Explanation:** Archive extraction without path validation enables zip slip attacks overwriting system files.[23][25]

**Bad Pattern 3:** `os.path.join()` with user input
```python
import os
path = os.path.join(base_dir, user_filename)
# No validation of resulting path
```
**Explanation:** `os.path.join()` doesn't prevent traversal when user input contains `../` sequences.[24][26]

**Regex (starter pattern):** `(open\s*$$|tarfile\.(open|extractall)|zipfile\..*extract)\s*$$`

**Reference(s):** CVE-2007-4559, OWASP Path Traversal[23][26][27]

## XML External Entity (XXE)

**Bad Pattern 1:** `xml.etree.ElementTree.parse()` with external entities enabled
```python
import xml.etree.ElementTree as ET
tree = ET.parse(user_xml_file)  # May process external entities
```
**Explanation:** Default XML parsers may resolve external entities, leading to file disclosure or SSRF attacks.[28][29]

**Bad Pattern 2:** `xml.sax.parse()` without entity restrictions
```python
import xml.sax
parser = xml.sax.make_parser()
parser.parse(xml_input)  # Processes external entities
```
**Explanation:** SAX parsers can be exploited for XXE attacks when entity processing isn't disabled.[29][30]

**Bad Pattern 3:** `lxml.etree.parse()` with resolve_entities=True
```python
from lxml import etree
doc = etree.parse(xml_file, parser=etree.XMLParser(resolve_entities=True))
```
**Explanation:** Explicitly enabling entity resolution makes applications vulnerable to XXE exploitation.[28][31]

**Regex (starter pattern):** `(xml\.(etree|sax)|lxml\.etree)\.(parse|XMLParser)`

**Reference(s):** CVE-2017-9233, OWASP XXE Prevention[32][28][31]

## Server-Side Template Injection (SSTI)

**Bad Pattern 1:** `render_template_string()` with user input
```python
from flask import render_template_string
template = request.form.get('template')
return render_template_string(template)  # Renders user-controlled templates
```
**Explanation:** Jinja2 template injection allows code execution through template syntax when user input is directly rendered.[33][34]

**Bad Pattern 2:** `Template().render()` with unsanitized data
```python
from jinja2 import Template
tmpl = Template(user_template)
output = tmpl.render()  # Executes template code
```
**Explanation:** Direct template rendering of user input enables server-side code execution via template expressions.[35][36]

**Bad Pattern 3:** String concatenation in template contexts
```python
template_content = f"<h1>Hello {{{{ {user_input} }}}}</h1>"
return render_template_string(template_content)
```
**Explanation:** Embedding user input into template syntax allows template injection attacks.[33][37]

**Regex (starter pattern):** `(render_template_string|Template\s*$$.*$$\.render)\s*$$`

**Reference(s):** CVE-2024-4r7v-whpg-8rx3, OWASP SSTI[35][33][38]

## Insecure Deserialization

**Bad Pattern 1:** `pickle.load()` from untrusted sources
```python
import pickle
with open(user_file, 'rb') as f:
    data = pickle.load(f)  # Deserializes malicious objects
```
**Explanation:** Pickle deserialization can execute arbitrary code during object reconstruction via magic methods.[6][39]

**Bad Pattern 2:** `yaml.load()` without safe loader
```python
import yaml
config = yaml.load(user_data)  # Uses unsafe loader by default
```
**Explanation:** PyYAML's default loader can instantiate arbitrary Python objects, leading to code execution.[5][40]

**Bad Pattern 3:** `marshal.loads()` on user data
```python
import marshal
obj = marshal.loads(user_input)  # Deserializes bytecode
```
**Explanation:** Marshal can deserialize Python bytecode, potentially executing malicious code.[5][41]

**Regex (starter pattern):** `(pickle\.loads?|yaml\.load|marshal\.loads?)\s*$$`

**Reference(s):** CVE-2022-42919, Snyk Pickle Vulnerabilities[6][22][42]

## CRLF Injection

**Bad Pattern 1:** `urllib.request.urlopen()` with user-controlled URLs containing CRLF
```python
import urllib.request
url = f"http://example.com/{user_input}"
urllib.request.urlopen(url)  # Doesn't sanitize CRLF sequences
```
**Explanation:** CRLF characters in URLs can inject HTTP headers, enabling response splitting attacks.[43][44]

**Bad Pattern 2:** `http.client.putheader()` with unsanitized values
```python
import http.client
conn = http.client.HTTPConnection('example.com')
conn.putheader('Custom-Header', user_value)  # No CRLF filtering
```
**Explanation:** Direct header injection allows manipulation of HTTP responses via CRLF sequences.[44][45]

**Bad Pattern 3:** URL construction with user input
```python
redirect_url = f"Location: {user_url}\r\nSet-Cookie: evil=1"
```
**Explanation:** Concatenating user input into HTTP headers enables header injection attacks.[43][46]

**Regex (starter pattern):** `(urllib\.(request|parse)|http\.client)\.|putheader\s*$$`

**Reference(s):** CVE-2016-5699, CVE-2019-9947[43][44][47]

## LDAP Injection

**Bad Pattern 1:** String concatenation in LDAP filters
```python
import ldap
username = request.form['username']
filter_str = f"(uid={username})"  # No LDAP escaping
conn.search_s(base_dn, ldap.SCOPE_SUBTREE, filter_str)
```
**Explanation:** Direct concatenation allows LDAP filter manipulation through special characters like `*()&|`.[48][49]

**Bad Pattern 2:** `.format()` in LDAP queries
```python
ldap_filter = "(&(objectClass=user)(cn={}))".format(user_input)
result = conn.search_s(base, ldap.SCOPE_SUBTREE, ldap_filter)
```
**Explanation:** String formatting doesn't escape LDAP metacharacters, enabling filter bypass.[50][51]

**Bad Pattern 3:** Unvalidated search parameters
```python
search_term = request.GET.get('search')
filter = f"(|(cn={search_term})(mail={search_term}))"
```
**Explanation:** Multiple injection points without validation amplify LDAP injection risks.[49][52]

**Regex (starter pattern):** `(ldap\.(search|search_s)|\.format$$$$.*ldap|f".*$$.*=.*\{)`

**Reference(s):** OWASP LDAP Injection Prevention, Trendmicro LDAP Guide[49][51][53]

## File Upload Vulnerabilities

**Bad Pattern 1:** Unrestricted file extensions
```python
uploaded_file = request.files['file']
filename = uploaded_file.filename
uploaded_file.save(f"/uploads/{filename}")  # No extension validation
```
**Explanation:** Allowing arbitrary file extensions enables upload of executable scripts that can be accessed remotely.[54][55]

**Bad Pattern 2:** MIME type validation only
```python
if uploaded_file.content_type == 'image/jpeg':
    uploaded_file.save(path)  # MIME type can be spoofed
```
**Explanation:** MIME types are client-controlled and can be easily manipulated by attackers.[56][57]

**Bad Pattern 3:** No file content validation
```python
file_data = request.files['upload'].read()
with open(f"uploads/{filename}", 'wb') as f:
    f.write(file_data)  # No content inspection
```
**Explanation:** Files may contain malicious code or exploits that execute when accessed or processed.[54][58]

**Regex (starter pattern):** `\.(save|write)\s*$$.*uploads?.*$$|files$$.*$$\.filename`

**Reference(s):** PortSwigger File Upload Guide, AWS File Upload Security[54][56][58]

## Regular Expression Denial of Service (ReDoS)

**Bad Pattern 1:** Nested quantifiers in regex
```python
import re
pattern = r"(a+)+"  # Catastrophic backtracking
re.match(pattern, user_input)
```
**Explanation:** Nested quantifiers cause exponential backtracking on non-matching input, leading to CPU exhaustion.[59][60]

**Bad Pattern 2:** Alternation with overlapping patterns
```python
regex = r"(a|a)*$"
re.search(regex, attacker_string)  # Multiple matching paths
```
**Explanation:** Overlapping alternatives create multiple parsing paths, causing performance degradation.[61][62]

**Bad Pattern 3:** User-controlled regex patterns
```python
user_pattern = request.form['regex']
re.compile(user_pattern).search(text)  # Malicious regex
```
**Explanation:** Allowing users to provide regex patterns enables ReDoS attacks through crafted expressions.[60][62]

**Regex (starter pattern):** `re\.(match|search|compile|findall)\s*$$`

**Reference(s):** GitHub ReDoS Guide, OWASP ReDoS[59][61][62]

Sources
- [1] Code Injection Vulnerability Caused by eval() in ... https://github.com/letta-ai/letta/issues/2613
- [2] CWE-94: Improper Control of Generation of Code ... - Mitre https://cwe.mitre.org/data/definitions/94.html
- [3] Code injection prevention for Python https://semgrep.dev/docs/cheat-sheets/python-code-injection
- [4] PickleBall: Secure Deserialization of Pickle-based Machine ... https://arxiv.org/html/2508.15987v1
- [5] Insecure Deserialization https://docs.cobalt.io/bestpractices/insecure-deserialization/
- [6] Remote Code Execution via Insecure Deserialization in ... https://github.com/iop-apl-uw/basestation3/issues/6
- [7] CVE-2025-3248 – Unauthenticated Remote Code ... https://www.offsec.com/blog/cve-2025-3248/
- [8] SQL Injection in Python: Example and Prevention https://brightsec.com/blog/sql-injection-python/
- [9] Fixing SQL Injection Vulnerabilities in Flask (Python) https://www.stackhawk.com/blog/finding-and-fixing-sql-injection-vulnerabilities-in-flask-python/
- [10] Preventing SQL Injection Attacks With Python https://realpython.com/prevent-python-sql-injection/
- [11] Avoid SQL injections https://docs.datadoghq.com/security/code_security/static_analysis/static_analysis_rules/python-security/variable-sql-statement-injection/
- [12] python-sql SQL injection vulnerability · CVE-2024-9774 https://github.com/advisories/GHSA-pq9p-pc3p-9hm4
- [13] Server Side Request Forgery - A10 OWASP Top 10 👁‍🗨 https://www.wallarm.com/what/server-side-request-forgery
- [14] What is SSRF (Server-side request forgery)? Tutorial & ... https://portswigger.net/web-security/ssrf
- [15] OWASP Top 10 Vulnerabilities: Updated https://www.geeksforgeeks.org/ethical-hacking/owasp-top-10-vulnerabilities-and-preventions/
- [16] Server-Side Request Forgery Prevention Cheat Sheet https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html
- [17] A10:2021 – Server-Side Request Forgery (SSRF) ... https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_(SSRF)/
- [18] Command injection in Python: examples and prevention https://snyk.io/blog/command-injection-python-prevention-examples/
- [19] Command injection prevention for Python https://semgrep.dev/docs/cheat-sheets/python-command-injection
- [20] Secure Python Code: safe usage of the subprocess module https://www.codiga.io/blog/python-subprocess-security/
- [21] Introduction to Command Injection Vulnerability https://www.cobalt.io/blog/introduction-to-command-injection-vulnerability
- [22] Latest Python Vulnerabilities https://feedly.com/cve/vendors/python
- [23] Understand the path traversal bug in Python's tarfile module https://www.securecodewarrior.com/article/traversal-bug-in-pythons-tarfile-module
- [24] Django Path Traversal Guide: Examples and Prevention https://www.stackhawk.com/blog/django-path-traversal-guide-examples-and-prevention/
- [25] Zip Slip Vulnerability https://security.snyk.io/research/zip-slip-vulnerability
- [26] Path Traversal https://owasp.org/www-community/attacks/Path_Traversal
- [27] A guide to path traversal and arbitrary file read attacks https://www.yeswehack.com/learn-bug-bounty/practical-guide-path-traversal-attacks
- [28] XML external entity expansion - CodeQL - GitHub https://codeql.github.com/codeql-query-help/python/py-xxe/
- [29] How to Mitigate XXE Vulnerabilities in Python https://www.acunetix.com/blog/web-security-zone/how-to-mitigate-xxe-vulnerabilities-in-python/
- [30] Django XML External Entities (XXE) Guide https://www.stackhawk.com/blog/django-xml-external-entities-xxe-guide-examples-and-prevention/
- [31] XML External Entity Prevention - OWASP Cheat Sheet Series https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html
- [32] XML External Entity https://www.geeksforgeeks.org/ethical-hacking/xml-external-entity-xxe-processing/
- [33] Finding and Fixing SSTI Vulnerabilities in Flask (Python) ... https://www.stackhawk.com/blog/finding-and-fixing-ssti-vulnerabilities-in-flask-python-with-stackhawk/
- [34] Server-side template injection exploitation with RCE ... https://www.yeswehack.com/learn-bug-bounty/server-side-template-injection-exploitation
- [35] Server-side template injection (SSTI) - Jinja2 https://dojo-yeswehack.com/learn/vulnerabilities/jinja2
- [36] What is Server Side Template Injection (SSTI) In Flask ... https://payatu.com/blog/server-side-template-injectionssti/
- [37] Server Side Template Injection with Jinja2 https://onsecurity.io/article/server-side-template-injection-with-jinja2/
- [38] Server Side Template Injection in Jinja2 allows Remote ... https://github.com/dgtlmoon/changedetection.io/security/advisories/GHSA-4r7v-whpg-8rx3
- [39] Python pickle serialization - Web Application Vulnerabilities https://www.invicti.com/web-application-vulnerabilities/python-pickle-serialization
- [40] avoid-pickle https://semgrep.dev/r/serialization.pickle.avoid-pickle
- [41] Python pickle serialization - Vulnerabilities https://www.acunetix.com/vulnerabilities/web/python-pickle-serialization/
- [42] Python CVEs and Security Vulnerabilities https://app.opencve.io/cve/?product=python&vendor=python
- [43] Python urllib CRLF injection vulnerability Abstract: Principles https://bugs.python.org/file48206/python-urllib-CRLF-injection-vulnerability.pdf
- [44] Python Improper Neutralization of CRLF Sequences in ... https://www.invicti.com/web-application-vulnerabilities/python-improper-neutralization-of-crlf-sequences-in-http-headers-http-response-splitting-vulnerability-cve-2016-5699
- [45] CRLF injection found in popular Python dependency, urllib3 https://snyk.io/blog/crlf-injection-found-in-popular-python-dependency/
- [46] CRLF Injection Attack https://www.geeksforgeeks.org/linux-unix/crlf-injection-attack/
- [47] Python Improper Neutralization of CRLF Sequences ... https://www.acunetix.com/vulnerabilities/web/python-improper-neutralization-of-crlf-sequences-crlf-injection-vulnerability-cve-2019-9947/
- [48] How to fix LDAP injection vulnerability? https://www.tencentcloud.com/techpedia/124043
- [49] LDAP injection - Python - Knowledge Base https://help.fluidattacks.com/portal/en/kb/articles/criteria-fixes-python-107
- [50] LDAP Injection Guide: Types, Examples, Prevention https://brightsec.com/blog/ldap-injection/
- [51] How to Avoid LDAP Injection Attacks https://www.trendmicro.com/en_my/research/23/c/avoid-ldap-injection-attacks.html
- [52] What is LDAP injection? | Tutorial & examples https://learn.snyk.io/lesson/ldap-injection/
- [53] LDAP Injection Prevention - OWASP Cheat Sheet Series https://cheatsheetseries.owasp.org/cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.html
- [54] File uploads | Web Security Academy https://portswigger.net/web-security/file-upload
- [55] File Upload Vulnerabilities https://www.cobalt.io/blog/file-upload-vulnerabilities
- [56] File Upload Bypass: Upload Forms Threat Explained https://www.acunetix.com/websitesecurity/upload-forms-threat/
- [57] Insecure file upload - Python - Knowledge Base https://help.fluidattacks.com/portal/en/kb/articles/criteria-fixes-python-027
- [58] Unrestricted upload of dangerous file type https://docs.aws.amazon.com/codeguru/detector-library/python/unrestricted-file-upload/
- [59] How to fix a ReDoS https://github.blog/security/how-to-fix-a-redos/
- [60] Understanding ReDoS Attack https://www.geeksforgeeks.org/ethical-hacking/understanding-redos-attack/
- [61] doyensec/regexploit: Find regular expressions which are ... https://github.com/doyensec/regexploit
- [62] Regular expression Denial of Service - ReDoS https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS