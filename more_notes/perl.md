# Deep Research — Server-Side Vulnerabilities & Dangerous Code Patterns in Perl

## SQL Injection

**Bad Pattern 1: Direct string interpolation in DBI queries**
```perl
$sth = $dbh->do("SELECT * FROM users WHERE username = '$username'");
```
Explanation: User input is directly concatenated into SQL query without sanitization, allowing attackers to inject malicious SQL code [1].

**Bad Pattern 2: Using prepare() without placeholders**
```perl
$sth = $dbh->prepare("SELECT * FROM users WHERE id = $user_id");
$sth->execute();
```
Explanation: Even with prepare(), direct variable interpolation bypasses parameter binding protections [2].

**Bad Pattern 3: Building dynamic queries with concatenation**
```perl
$sql = "SELECT * FROM table WHERE condition = '" . $input . "'";
$sth = $dbh->prepare($sql);
```
Explanation: String concatenation creates the same vulnerability as direct interpolation in do() method [1][3].

Regex (starter pattern): `(->do$$|->prepare$$)[^?]*[\$@%]`

Reference(s): CVE research on Perl DBI vulnerabilities, UW-Madison Software Security Course [1], bobby-tables.com Perl guide [2]

## Command Injection

**Bad Pattern 1: Using system() with user input**
```perl
system("ping -c 3 $ip_address");
```
Explanation: Direct execution of shell commands with unvalidated user input allows arbitrary command injection [4][5].

**Bad Pattern 2: Unsafe use of backticks**
```perl
$output = `ls -l $directory`;
```
Explanation: Backtick operator executes shell commands and can be exploited with command separators like semicolons or pipes [4][5].

**Bad Pattern 3: Using open() with pipe operations**
```perl
open(FH, "$command|") or die;
```
Explanation: Open with pipe allows execution of arbitrary commands when user input is used in the command variable [6][7].

Regex (starter pattern): `(system$$|`[^`]*\$|open$$[^,]*\|)`

Reference(s): CVE-2000-0500 (CVSWeb), OWASP Command Injection Testing Guide [4], Perl CGI Security Notes [7]

## Path Traversal

**Bad Pattern 1: Direct file path construction**
```perl
open(FILE, "/var/www/files/" . $filename) or die;
```
Explanation: Concatenating user input to file paths allows directory traversal attacks using "../" sequences [8][9].

**Bad Pattern 2: Using param() input in file operations**
```perl
my $file = param("file");
open(FH, "/uploads/$file");
```
Explanation: CGI parameter input directly used in file paths without sanitization enables access to arbitrary files [9][10].

**Bad Pattern 3: Two-argument open() with user input**
```perl
open(HANDLE, $user_supplied_filename);
```
Explanation: Two-argument open() is inherently unsafe as it allows pipe operations and file descriptor manipulation [7][11].

Regex (starter pattern): `open$$[^,]*[\$@%][^,]*$$|\/[^\/]*[\$@%]`

Reference(s): CWE-22, CWE-23, CVE research on Perl path traversal [8][9], Perl Security documentation [7]

## Code Injection (eval)

**Bad Pattern 1: Direct eval() with user input**
```perl
my $code = param("action");
eval($code);
```
Explanation: Evaluating user-controlled strings as Perl code allows arbitrary code execution [12][13][14].

**Bad Pattern 2: Building code strings dynamically**
```perl
my $action = param("action");
my $code = "process_$action()";
eval($code);
```
Explanation: Even with controlled prefixes, attackers can inject malicious code through careful crafting of input [13][14].

**Bad Pattern 3: Using eval() for configuration**
```perl
my $config = "setting = '$value'";
eval($config);
```
Explanation: Configuration values can contain code that gets executed when eval'd without proper validation [15].

Regex (starter pattern): `eval$$[^)]*[\$@%]`

Reference(s): CWE-94, CWE-95, CVE-2023-0089, CVE-2023-0090 (Proofpoint Enterprise Protection) [15], CWE examples [13][14]

## File Upload Vulnerabilities

**Bad Pattern 1: Unrestricted file extension acceptance**
```perl
my $upload = $q->upload('file');
my $filename = $upload->filename;
open(OUT, ">uploads/$filename");
```
Explanation: Accepting any file extension allows upload of executable scripts that can be accessed via web server [16][17].

**Bad Pattern 2: MIME type validation only**
```perl
if ($q->upload('file')->type eq 'image/jpeg') {
    # Save file
}
```
Explanation: MIME types can be easily spoofed by attackers to bypass restrictions while uploading malicious files [16][18].

**Bad Pattern 3: Directory traversal in upload paths**
```perl
my $filename = "../../../etc/passwd";
open(OUT, ">uploads/$filename");
```
Explanation: Unvalidated filenames can contain path traversal sequences leading to overwriting critical system files [19].

Regex (starter pattern): `upload.*->filename|>.*[\$@%].*filename`

Reference(s): File Upload Security research [16][17], Acunetix File Upload Vulnerabilities guide [18]

## XML External Entity (XXE)

**Bad Pattern 1: XML::LibXML with external DTD loading**
```perl
my $parser = XML::LibXML->new();
$parser->load_ext_dtd(1);
my $doc = $parser->parse_string($xml_input);
```
Explanation: Enabling external DTD loading allows attackers to read local files and perform SSRF attacks [20][21].

**Bad Pattern 2: Default XML::Simple configuration**
```perl
use XML::Simple;
my $xs = XML::Simple->new();
my $data = $xs->XMLin($user_xml);
```
Explanation: Default XML parsers often have XXE vulnerabilities enabled, allowing external entity processing [22][23].

**Bad Pattern 3: XML::Twig without security restrictions**
```perl
use XML::Twig;
my $twig = XML::Twig->new();
$twig->parse($untrusted_xml);
```
Explanation: Without proper configuration, XML::Twig processes external entities leading to file disclosure [23].

Regex (starter pattern): `XML::(LibXML|Simple|Twig).*parse|->parse.*[\$@%]`

Reference(s): CVE research on Perl XML libraries, SNYK-DEBIAN13-LIBSPREADSHEETPARSEXLSXPERL-6174433 [22], XML::Twig vulnerabilities [23]

## Server-Side Request Forgery (SSRF)

**Bad Pattern 1: LWP::UserAgent with user-controlled URLs**
```perl
use LWP::UserAgent;
my $ua = LWP::UserAgent->new;
my $response = $ua->get($user_url);
```
Explanation: Making HTTP requests to user-supplied URLs enables attackers to probe internal networks and services [24][25].

**Bad Pattern 2: HTTP::Request with unvalidated destinations**
```perl
my $req = HTTP::Request->new(GET => $target_url);
my $res = $ua->request($req);
```
Explanation: Unvalidated request destinations can be used to access cloud metadata services or internal APIs [24][26].

**Bad Pattern 3: Using curl or wget via system calls**
```perl
system("wget $url -O output.txt");
```
Explanation: Combining command injection with HTTP requests amplifies SSRF risks through shell execution [24].

Regex (starter pattern): `LWP::UserAgent|HTTP::Request.*[\$@%]|wget.*[\$@%]|curl.*[\$@%]`

Reference(s): OWASP SSRF guidance [24], Server-Side Request Forgery research [25][26]

## LDAP Injection

**Bad Pattern 1: Direct string interpolation in LDAP filters**
```perl
my $filter = "(&(uid=$username)(objectClass=person))";
my $result = $ldap->search(filter => $filter);
```
Explanation: User input directly embedded in LDAP filters allows manipulation of search logic and unauthorized data access [27][28].

**Bad Pattern 2: Building DN strings with user input**
```perl
my $dn = "uid=$user_id,ou=people,dc=example,dc=com";
$ldap->bind($dn, password => $password);
```
Explanation: Unescaped user input in Distinguished Names can alter LDAP tree navigation and authentication [27][29].

**Bad Pattern 3: Using Net::LDAP without input escaping**
```perl
my $search_filter = "(cn=$search_term)";
$ldap->search(base => $base_dn, filter => $search_filter);
```
Explanation: Without proper escaping using Net::LDAP::Util, special characters can modify filter semantics [27].

Regex (starter pattern): `filter.*[\$@%]|Net::LDAP.*search.*[\$@%]`

Reference(s): CVE-2012-3981 (Bugzilla LDAP injection) [27], OWASP LDAP Injection Prevention [29]

## Format String Vulnerabilities

**Bad Pattern 1: Using sprintf/printf with user-controlled format strings**
```perl
printf($user_input);
```
Explanation: User-controlled format strings can cause memory corruption and potentially arbitrary code execution [30][31][32].

**Bad Pattern 2: Logging with unvalidated format strings**
```perl
my $log_msg = param("message");
printf(LOGFILE $log_msg);
```
Explanation: Format specifiers in log messages can be exploited to read memory contents or cause crashes [33][34].

**Bad Pattern 3: Error messages with format vulnerabilities**
```perl
die sprintf($error_template, $user_data);
```
Explanation: Even in error handling, format string vulnerabilities can be exploited for information disclosure [32].

Regex (starter pattern): `printf$$[^,]*[\$@%][^,]*$$|sprintf$$[^,]*[\$@%]`

Reference(s): CVE research on Perl format string bugs, Webmin format string vulnerability [32], GitHub security research [30]

## Insecure Deserialization

**Bad Pattern 1: Using Storable with untrusted data**
```perl
use Storable qw(thaw);
my $data = thaw($serialized_input);
```
Explanation: Deserializing untrusted data can lead to arbitrary code execution through crafted Perl objects [35][36].

**Bad Pattern 2: eval() on serialized structures**
```perl
my $perl_code = $serialized_data;
my $obj = eval($perl_code);
```
Explanation: Using eval to deserialize data is extremely dangerous as it executes arbitrary Perl code directly [36].

**Bad Pattern 3: YAML::Load with user input**
```perl
use YAML;
my $data = YAML::Load($user_yaml);
```
Explanation: YAML deserialization can instantiate arbitrary Perl objects, potentially leading to code execution [37].

Regex (starter pattern): `(Storable::thaw|YAML::Load|eval.*[\$@%].*serializ)`

Reference(s): Insecure Deserialization research [35][37][36], OWASP guidance on deserialization

- Sources
- [1] Chapter 3.8.1: SQL Injection Attacks https://research.cs.wisc.edu/mist/SoftwareSecurityCourse/Chapters/3_8_1-SQL-Injections.pdf
- [2] bobby-tables.com: A guide to preventing SQL injection in Perl https://bobby-tables.com/perl
- [3] How can I protect against SQL injection attacks using Perl's ... https://stackoverflow.com/questions/2300765/how-can-i-protect-against-sql-injection-attacks-using-perls-dbi
- [4] Testing for Command Injection https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/12-Testing_for_Command_Injection
- [5] Chapter 3.8.2: Command Injections https://research.cs.wisc.edu/mist/SoftwareSecurityCourse/Chapters/3_8_2-Command-Injections.pdf
- [6] CVSWeb Developer CVSWeb 1.80 - Insecure Perl 'open' ... https://www.exploit-db.com/exploits/20073
- [7] Perl CGI Security Notes by Chris https://www.xed.ch/lwm/securitynotes.html
- [8] CWE-22: Improper Limitation of a Pathname to a Restricted ... https://cwe.mitre.org/data/definitions/22.html
- [9] CWE-23: Relative Path Traversal (4.18) - Mitre https://cwe.mitre.org/data/definitions/23.html
- [10] Local File Inclusions in Perl/CGI https://labs.detectify.com/writeups/local-file-inclusions-in-perl-cgi/
- [11] perl open() injection prevention https://stackoverflow.com/questions/26614348/perl-open-injection-prevention
- [12] Perl code injection https://portswigger.net/kb/issues/00100e00_perl-code-injection
- [13] CWE-95: Improper Neutralization of Directives in Dynamically ... https://cwe.mitre.org/data/definitions/95.html
- [14] CWE-94: Improper Control of Generation of Code ... - Mitre https://cwe.mitre.org/data/definitions/94.html
- [15] Proofpoint Enterprise Protection perl eval vulnerabilities https://www.proofpoint.com/us/security/security-advisories/pfpt-sa-2023-0001
- [16] Complete file upload vulnerabilities https://www.infosecinstitute.com/resources/hacking/file-upload-vulnerabilities/
- [17] File Upload Vulnerabilities https://www.cobalt.io/blog/file-upload-vulnerabilities
- [18] File Upload Bypass: Upload Forms Threat Explained https://www.acunetix.com/websitesecurity/upload-forms-threat/
- [19] File upload vulnerabilities https://www.verylazytech.com/file-upload-vulnerabilities
- [20] XML Parser Vulnerabilities https://www.usenix.org/sites/default/files/conference/protected-files/woot16_slides_spath.pdf
- [21] XML External Entity (XXE) Attacks and How to Avoid Them https://www.invicti.com/blog/web-security/xxe-xml-external-entity-attacks/
- [22] XML External Entity (XXE) Injection in libspreadsheet- ... https://security.snyk.io/vuln/SNYK-DEBIAN13-LIBSPREADSHEETPARSEXLSXPERL-6174433
- [23] XML External Entity (XXE) Injection in libxml-twig-perl https://security.snyk.io/vuln/SNYK-DEBIAN9-LIBXMLTWIGPERL-312829
- [24] Server Side Request Forgery https://owasp.org/www-community/attacks/Server_Side_Request_Forgery
- [25] What Is Server-Side Request Forgery ( SSRF)? https://www.f5.com/glossary/ssrf
- [26] Server-Side Request Forgery: What It Is & How To Fix It https://www.wiz.io/academy/server-side-request-forgery
- [27] How To Identify and Prevent LDAP Injection (Part 2) - Praetorian https://www.praetorian.com/blog/how-to-identify-and-prevent-ldap-injection-part-2/
- [28] LDAP injection https://portswigger.net/kb/issues/00100500_ldap-injection
- [29] LDAP Injection Prevention - OWASP Cheat Sheet Series https://cheatsheetseries.owasp.org/cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.html
- [30] An introduction to the hidden attack surface of interpreted ... https://github.blog/security/vulnerability-research/now-you-c-me-now-you-dont/
- [31] Testing for format string vulnerability https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/07-Input_Validation_Testing/13.3-Testing_for_Format_String
- [32] HTTP:EXPLOIT:WEBMIN-FS-INT https://www.juniper.net/us/en/threatlabs/ips-signatures/detail.HTTP:EXPLOIT:WEBMIN-FS-INT.html
- [33] Format String Vulnerability - Hacking Lab https://hackinglab.cz/en/blog/format-string-vulnerability/
- [34] Internet Bug Bounty | Report #271330 - Format string ... https://hackerone.com/reports/271330
- [35] Insecure deserialization | Web Security Academy https://portswigger.net/web-security/deserialization
- [36] Insecure Deserialization https://owasp.org/www-community/vulnerabilities/Insecure_Deserialization
- [37] Insecure De-serialization: Millions of Applications May Be ... https://hackers-arise.com/insecure-de-serialization-millions-of-applications-may-be-vulnerable/