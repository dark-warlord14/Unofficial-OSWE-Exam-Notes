# Deep Research — Server-Side Vulnerabilities & Dangerous Code Patterns in .NET

## SQL Injection

**Bad Pattern 1: String concatenation in SqlCommand**
```csharp
string query = "SELECT * FROM Users WHERE Username = '" + userInput + "'";
SqlCommand cmd = new SqlCommand(query, connection);
```
**Explanation:** Direct concatenation of user input into SQL queries allows attackers to inject malicious SQL statements [1][2].

**Bad Pattern 2: Dynamic query building with string interpolation**
```csharp
var query = $"SELECT * FROM Products WHERE NAME LIKE '{searchString}%'";
```
**Explanation:** String interpolation is equally vulnerable to SQL injection as traditional concatenation [2].

**Bad Pattern 3: Using ExecuteNonQuery with concatenated strings**
```csharp
command.CommandText = "DELETE FROM Users WHERE ID = " + userId;
command.ExecuteNonQuery();
```
**Explanation:** Any SQL execution method with concatenated user input creates injection vulnerabilities [2][3].

**Regex (starter pattern):** `(SqlCommand|ExecuteNonQuery|ExecuteScalar|ExecuteReader).*[\+\$\{].*[\"\']`

**Reference(s):** Microsoft SQL Injection documentation [1], .NET SQL Injection Tutorial [2]

***

## XML External Entity (XXE) Attacks

**Bad Pattern 1: XmlDocument with XmlUrlResolver**
```csharp
XmlDocument xmlDoc = new XmlDocument();
xmlDoc.XmlResolver = new XmlUrlResolver();
xmlDoc.LoadXml(userXml);
```
**Explanation:** XmlUrlResolver allows loading of external entities, enabling XXE attacks to read sensitive files or perform SSRF [4][5].

**Bad Pattern 2: XmlReader with insecure DtdProcessing**
```csharp
XmlReaderSettings settings = new XmlReaderSettings();
settings.DtdProcessing = DtdProcessing.Parse;
settings.XmlResolver = new XmlUrlResolver();
```
**Explanation:** Enabling DTD processing with XmlUrlResolver allows external entity resolution and XXE exploitation [5][6].

**Bad Pattern 3: XmlTextReader without proper configuration**
```csharp
XmlTextReader reader = new XmlTextReader(stream);
// Default settings are unsafe in .NET Framework < 4.5.2
```
**Explanation:** In .NET Framework versions prior to 4.5.2, XmlTextReader is unsafe by default and vulnerable to XXE [6].

**Regex (starter pattern):** `(XmlDocument|XmlReader|XmlTextReader).*[\.](XmlResolver|DtdProcessing)`

**Reference(s):** StackOverflow XXE Prevention [4], Site24x7 XXE Guide [5], OWASP XXE Prevention [6]

***

## Server-Side Request Forgery (SSRF)

**Bad Pattern 1: HttpClient with user-controlled URL**
```csharp
var response = await httpClient.GetAsync(userProvidedUrl);
```
**Explanation:** Allowing unvalidated URLs enables SSRF attacks against internal services and cloud metadata endpoints [7][8].

**Bad Pattern 2: WebRequest.Create with untrusted input**
```csharp
HttpWebRequest request = (HttpWebRequest)WebRequest.Create(metadataAddress);
```
**Explanation:** WebRequest.Create accepts any URI scheme and can be exploited to access internal resources [8][9].

**Bad Pattern 3: Using HttpWebRequest without URL validation**
```csharp
var request = WebRequest.Create(uri);
var response = request.GetResponse();
```
**Explanation:** Direct creation of web requests with user input enables attackers to forge requests to arbitrary hosts [10][11].

**Regex (starter pattern):** `(HttpClient|WebRequest|HttpWebRequest).*[\.](GetAsync|Create).*[$$].*[userInput|url|Uri]`

**Reference(s):** FluidAttacks SSRF Guide [7], StackOverflow WebRequest SSRF [8], Veracode SSRF HttpClient [9]

***

## Path Traversal

**Bad Pattern 1: Path.Combine with unsanitized input**
```csharp
var filePath = Path.Combine(contentRootPath, fileName);
using (FileStream stream = File.Create(filePath))
```
**Explanation:** Path.Combine ignores the first parameter if the second is an absolute path, enabling directory traversal [12][13].

**Bad Pattern 2: File operations with concatenated paths**
```csharp
string fullPath = baseDirectory + "/" + userFileName;
return File.ReadAllBytes(fullPath);
```
**Explanation:** Direct string concatenation allows "../" sequences to escape the intended directory [14][15].

**Bad Pattern 3: DirectoryInfo with unvalidated paths**
```csharp
DirectoryInfo dir = new DirectoryInfo(userPath);
dir.Create();
```
**Explanation:** Creating directories with user-controlled paths allows traversal outside the web root [12][16].

**Regex (starter pattern):** `(Path\.Combine|File\.|Directory\.|DirectoryInfo).*[\+\$\{].*[userInput|fileName]`

**Reference(s):** Microsoft Path Traversal Prevention [12], Praetorian Path.Combine Security [13], InfoSecWriteups Path Traversal [16]

***

## Command Injection

**Bad Pattern 1: Process.Start with user input**
```csharp
Process.Start("cmd.exe", $"/C echo {userInput} > output.txt");
```
**Explanation:** Concatenating user input into command arguments allows injection of additional commands [17][18].

**Bad Pattern 2: ProcessStartInfo with dynamic arguments**
```csharp
startInfo.Arguments = "/C " + commandFromUser;
process.Start();
```
**Explanation:** User-controlled command arguments enable OS command injection attacks [17][19].

**Bad Pattern 3: Process execution with string concatenation**
```csharp
var process = Process.Start("powershell", "-Command " + userCommand);
```
**Explanation:** Direct concatenation of user input into process arguments creates command injection vulnerabilities [18][20].

**Regex (starter pattern):** `Process\.Start.*[\+\$\{].*[userInput|command]`

**Reference(s):** StackHawk Command Injection [17], Microsoft CA3006 [18], Veracode Command Injection [20]

***

## Insecure Deserialization

**Bad Pattern 1: BinaryFormatter deserialization**
```csharp
BinaryFormatter formatter = new BinaryFormatter();
object obj = formatter.Deserialize(stream);
```
**Explanation:** BinaryFormatter can deserialize any type and execute arbitrary code during deserialization [21][22].

**Bad Pattern 2: NetDataContractSerializer with untrusted data**
```csharp
NetDataContractSerializer serializer = new NetDataContractSerializer();
var result = serializer.Deserialize(inputStream);
```
**Explanation:** NetDataContractSerializer is vulnerable to the same RCE attacks as BinaryFormatter [21][23].

**Bad Pattern 3: SoapFormatter deserialization**
```csharp
SoapFormatter formatter = new SoapFormatter();
return formatter.Deserialize(stream);
```
**Explanation:** SoapFormatter is equally dangerous and can execute arbitrary code through object construction [21][24].

**Regex (starter pattern):** `(BinaryFormatter|SoapFormatter|NetDataContractSerializer).*\.Deserialize`

**Reference(s):** Microsoft BinaryFormatter Security Guide [21], .NET Deserialization Cheat Sheet [25], GitHub Deserialization Issues [22]

***

## File Upload Vulnerabilities

**Bad Pattern 1: No file extension validation**
```csharp
var path = Path.Combine(Directory.GetCurrentDirectory(), file.FileName);
await file.CopyToAsync(new FileStream(path, FileMode.Create));
```
**Explanation:** Accepting files without extension validation allows upload of executable files like DLLs or scripts [26][27].

**Bad Pattern 2: Insufficient MIME type checking**
```csharp
if (file.ContentType == "image/jpeg") // Bypassable
    await SaveFile(file);
```
**Explanation:** MIME type headers can be easily spoofed by attackers to bypass content-type restrictions [27][28].

**Bad Pattern 3: Path.GetExtension without proper validation**
```csharp
var ext = Path.GetExtension(fileName);
if (ext != ".exe") await SaveFile(file); // Blacklist approach
```
**Explanation:** Blacklist-based validation is easily bypassed; whitelist approaches are more secure [26][29].

**Regex (starter pattern):** `(file\.CopyToAsync|File\.Create|SaveFile).*[fileName|file\.]`

**Reference(s):** FluidAttacks DLL Injection [26], FluidAttacks File Upload [27], PortSwigger File Upload [28]

***

## LDAP Injection

**Bad Pattern 1: DirectorySearcher with concatenated filter**
```csharp
searcher.Filter = "(&(" + UserNameAttribute + "=" + userName + "))";
```
**Explanation:** Concatenating user input into LDAP filters allows injection of malicious LDAP queries [30][31].

**Bad Pattern 2: DirectoryEntry constructor with untrusted input**
```csharp
DirectoryEntry de = new DirectoryEntry(path, username, userPassword);
```
**Explanation:** User-controlled credentials in DirectoryEntry can redirect authentication to attacker-controlled servers [30][32].

**Bad Pattern 3: Dynamic LDAP query construction**
```csharp
string filter = $"(cn={userInput}*)";
searcher.Filter = filter;
```
**Explanation:** String interpolation in LDAP filters is vulnerable to injection attacks that bypass authentication [33][34].

**Regex (starter pattern):** `(DirectorySearcher|DirectoryEntry).*[\.](Filter|new).*[\+\$\{].*[userInput]`

**Reference(s):** Security StackExchange LDAP Injection [30], Packt LDAP Injection Fix [31], Microsoft CA3005 [35]

***

## XPath Injection

**Bad Pattern 1: XPathNavigator with concatenated expressions**
```csharp
XPathExpression expr = nav.Compile("//user[name='" + userName + "']");
```
**Explanation:** Direct concatenation of user input into XPath queries allows attackers to modify query logic [36][37].

**Bad Pattern 2: XPathDocument with dynamic queries**
```csharp
var nodes = doc.SelectNodes($"//book[title='{userTitle}']");
```
**Explanation:** String interpolation in XPath queries is vulnerable to injection attacks [38][39].

**Bad Pattern 3: XmlNode.SelectSingleNode with user input**
```csharp
string xpath = "//employee[@id='" + employeeId + "']";
XmlNode node = xmlDoc.SelectSingleNode(xpath);
```
**Explanation:** Building XPath queries through concatenation allows injection of malicious XPath expressions [37][40].

**Regex (starter pattern):** `(XPathNavigator|SelectNodes|SelectSingleNode).*[\+\$\{].*[userInput]`

**Reference(s):** StackOverflow XPath Injection Prevention [36], Packt XPath Injection Fix [37], Microsoft CA3008 [39]

***

## Hardcoded Credentials

**Bad Pattern 1: Database connection strings in code**
```csharp
string connectionString = "Server=localhost;Database=app;User=sa;Password=admin123;";
```
**Explanation:** Hardcoded passwords in source code can be discovered through reverse engineering or code repository access [41][42].

**Bad Pattern 2: API keys in configuration**
```csharp
string apiKey = "sk-1234567890abcdef";
var client = new ApiClient(apiKey);
```
**Explanation:** Embedding secrets in code makes them accessible to anyone with source code access [41][43].

**Bad Pattern 3: Service account credentials in code**
```csharp
var creds = new NetworkCredential("serviceaccount", "P@ssw0rd123");
```
**Explanation:** Hardcoded service credentials create permanent backdoors that are difficult to rotate [44][45].

**Regex (starter pattern):** `(password|apikey|secret|credential).*[=:].*[\"'][a-zA-Z0-9\!\@\#\$\%\^\&\*]+[\"']`

**Reference(s):** Snyk Hardcoded Secrets [41], CWE-259 [42], InfoSec Credential Management [43]

***

## Regular Expression Denial of Service (ReDoS)

**Bad Pattern 1: Nested quantifiers in Regex**
```csharp
Regex regex = new Regex(@"(a+)+b");
regex.IsMatch(maliciousInput);
```
**Explanation:** Nested quantifiers can cause catastrophic backtracking leading to CPU exhaustion [46][47].

**Bad Pattern 2: Alternation with overlapping patterns**
```csharp
var pattern = @"(a|a)*b";
Regex.IsMatch(input, pattern);
```
**Explanation:** Overlapping alternation patterns create exponential backtracking possibilities [46][48].

**Bad Pattern 3: Unbounded repetition with complex groups**
```csharp
Regex.IsMatch(input, @"^(.*)*$");
```
**Explanation:** Complex patterns with unbounded repetition are vulnerable to ReDoS attacks [47][49].

**Regex (starter pattern):** `new Regex.*[$$$$\*\+\{\|$$]`

**Reference(s):** PVS-Studio ReDoS [46], Snyk ReDoS Tutorial [47], Threat Modeling ReDoS [48]

***

## Mass Assignment

**Bad Pattern 1: Automatic model binding without restrictions**
```csharp
public IActionResult UpdateUser(User user)
{
    _userService.Update(user); // Updates all properties
}
```
**Explanation:** Unrestricted model binding allows attackers to modify sensitive properties like roles or permissions [50][51].

**Bad Pattern 2: Direct model updates from HTTP parameters**
```csharp
var user = db.Users.Find(id);
TryUpdateModel(user);
```
**Explanation:** TryUpdateModel without field restrictions enables mass assignment attacks [51][52].

**Bad Pattern 3: JSON deserialization to domain models**
```csharp
var user = JsonConvert.DeserializeObject<User>(requestBody);
```
**Explanation:** Deserializing directly to domain models exposes all properties to potential manipulation [53][54].

**Regex (starter pattern):** `(TryUpdateModel|JsonConvert\.DeserializeObject|UpdateModel).*[<].*[>]`

**Reference(s):** Secure Code Warrior Mass Assignment [50], ASP.NET Mass Assignment Prevention [51], OWASP Mass Assignment [52]

***

## XML Bomb (Billion Laughs)

**Bad Pattern 1: DataSet.ReadXml with untrusted input**
```csharp
DataSet ds = new DataSet();
ds.ReadXml(userXmlStream);
```
**Explanation:** DataSet.ReadXml can be exploited with XML bombs to cause denial of service through memory exhaustion [55][56].

**Bad Pattern 2: XmlDocument loading without restrictions**
```csharp
XmlDocument doc = new XmlDocument();
doc.Load(xmlInputStream); // No entity expansion limits
```
**Explanation:** Unrestricted XML loading allows billion laughs attacks that exponentially expand entity references [56][57].

**Bad Pattern 3: XmlReader without MaxCharactersFromEntities**
```csharp
XmlReaderSettings settings = new XmlReaderSettings();
// No limits set - vulnerable to entity expansion
XmlReader.Create(stream, settings);
```
**Explanation:** Without entity expansion limits, XML parsers are vulnerable to DoS attacks through recursive entity definitions [57][58].

**Regex (starter pattern):** `(DataSet\.ReadXml|XmlDocument\.Load|XmlReader\.Create).*[(].*[stream|input]`

**Reference(s):** Microsoft CA2351 [55], MSDN XML DoS Attacks [56], Meziantou XML Vulnerabilities [57]

- Sources
- [1] SQL Injection - SQL Server https://learn.microsoft.com/en-us/sql/relational-databases/security/sql-injection?view=sql-server-ver17
- [2] SQL Injection and Prevention in C# ADO.NET https://dotnettutorials.net/lesson/sql-injection-and-prevention-in-csharp-ado-net/
- [3] SQL Injection Prevention - OWASP Cheat Sheet Series https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html
- [4] How to prevent XXE attack (XmlDocument in .NET) https://stackoverflow.com/questions/14230988/how-to-prevent-xxe-attack-xmldocument-in-net
- [5] How to Identify & Avoid XXE Vulnerabilities in .Net https://www.site24x7.com/learn/xxe-vulnerabilities.html
- [6] XML External Entity Prevention - OWASP Cheat Sheet Series https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html
- [7] Server-side request forgery (SSRF) - C-Sharp - Knowledge Base https://help.fluidattacks.com/portal/en/kb/articles/criteria-fixes-csharp-100
- [8] WebRequest.Create and SSRF vulnerability https://stackoverflow.com/questions/77653133/webrequest-create-and-ssrf-vulnerability
- [9] How to fix SSRF in the HttpClient request https://community.veracode.com/s/question/0D53n0000860XIgCAM/how-to-fix-ssrf-in-the-httpclient-request
- [10] What is SSRF (Server-side request forgery)? Tutorial & ... https://portswigger.net/web-security/ssrf
- [11] Server-Side Request Forgery: How to Easily Prevent Them https://brightsec.com/blog/ssrf-server-side-request-forgery/
- [12] How to prevent of path traversal in Asp.net core https://learn.microsoft.com/en-us/answers/questions/933973/how-to-prevent-of-path-traversal-in-asp-net-core
- [13] Path.Combine Security Issues in ASP.NET Applications https://www.praetorian.com/blog/pathcombine-security-issues-in-aspnet-applications/
- [14] Path Traversal https://owasp.org/www-community/attacks/Path_Traversal
- [15] What is path traversal, and how to prevent it? https://portswigger.net/web-security/file-path-traversal
- [16] ASP.NET CORE Path Traversal https://infosecwriteups.com/asp-net-core-path-traversal-e2bed792d171
- [17] NET Command Injection: Examples and Prevention https://www.stackhawk.com/blog/net-command-injection-examples-and-prevention/
- [18] CA3006: Review code for process command injection ... https://learn.microsoft.com/en-us/dotnet/fundamentals/code-analysis/quality-rules/ca3006
- [19] c# - OS Command Injection from Process.Start https://stackoverflow.com/questions/26536762/os-command-injection-from-process-start
- [20] CWE 78: OS Command Injection | ASP.Net https://www.veracode.com/security/dotnet/cwe-78/
- [21] Deserialization risks in use of BinaryFormatter and related ... https://learn.microsoft.com/en-us/dotnet/standard/serialization/binaryformatter-security-guide
- [22] BinaryFormatter is being removed in .NET 9 · Issue #98245 https://github.com/dotnet/runtime/issues/98245
- [23] Deserialization can be dangerous - Gérald Barré https://www.meziantou.net/deserialization-can-be-dangerous.htm
- [24] .NET Insecure Deserialization - Vulnerability & Exploit ... https://pentest-tools.com/vulnerabilities-exploits/net-insecure-deserialization_25975
- [25] SohelParashar/.Net-Deserialization-Cheat-Sheet https://github.com/SohelParashar/.Net-Deserialization-Cheat-Sheet
- [26] Insecure file upload - DLL Injection - C-Sharp - Knowledge Base https://help.fluidattacks.com/portal/en/kb/articles/criteria-fixes-csharp-413
- [27] Insecure file upload - C-Sharp - Knowledge Base https://help.fluidattacks.com/portal/en/kb/articles/criteria-fixes-csharp-027
- [28] File uploads | Web Security Academy https://portswigger.net/web-security/file-upload
- [29] File Upload https://www.securecodewarrior.com/guidelines/file-upload
- [30] C# LDAP Injection - IT Security Stack Exchange https://a.osmarks.net/content/security.stackexchange.com_en_all_2022-11/questions/101997/c-ldap-injection
- [31] Injection Flaws | ASP.NET Core 5 Secure Coding Cookbook https://subscription.packtpub.com/book/web_development/9781801071567/2/ch02lvl1sec21/fixing-ldap-injection
- [32] LDAP injection vulnerability with DirectoryEntry username ... https://stackoverflow.com/questions/59178153/ldap-injection-vulnerability-with-directoryentry-username-and-password
- [33] LDAP Injection Guide: Types, Examples, Prevention https://brightsec.com/blog/ldap-injection/
- [34] Prevent LDAP injection https://docs.datadoghq.com/security/code_security/static_analysis/static_analysis_rules/csharp-security/ldap-injection/
- [35] CA3005: Review code for LDAP injection vulnerabilities https://learn.microsoft.com/en-us/dotnet/fundamentals/code-analysis/quality-rules/ca3005
- [36] Preventing Xpath Injection on .net 2.0 https://stackoverflow.com/questions/15145071/preventing-xpath-injection-on-net-2-0
- [37] Fixing XPath injection https://subscription.packtpub.com/book/web-development/9781801071567/2/ch02lvl1sec22/fixing-xpath-injection
- [38] XPath injection - C-Sharp - Knowledge Base https://help.fluidattacks.com/portal/en/kb/articles/criteria-fixes-csharp-021
- [39] CA3008: Review code for XPath injection vulnerabilities https://learn.microsoft.com/en-us/dotnet/fundamentals/code-analysis/quality-rules/ca3008
- [40] StackHawk Docs for Plugin XPath Injection https://docs.stackhawk.com/vulnerabilities/90021/
- [41] Hardcoded secrets | Tutorial and examples https://learn.snyk.io/lesson/hardcoded-secrets/
- [42] CWE-259: Use of Hard-coded Password (4.18) - Mitre https://cwe.mitre.org/data/definitions/259.html
- [43] How to mitigate Credential Management Vulnerabilities https://www.infosecinstitute.com/resources/cryptography/how-to-mitigate-credential-management-vulnerabilities/
- [44] CWE-798: Use of Hard-coded Credentials (4.18) - Mitre https://cwe.mitre.org/data/definitions/798.html
- [45] Hard-coded credentials are security-sensitive https://rules.sonarsource.com/csharp/type/security%20hotspot/rspec-2068/
- [46] how can a regular expression cause a ReDoS vulnerability? https://pvs-studio.com/en/blog/posts/csharp/1007/
- [47] ReDoS | Tutorial & Examples https://learn.snyk.io/lesson/redos/
- [48] ReDoS: Regular Expression Denial of Service https://threat-modeling.com/redos-regular-expression-denial-of-service/
- [49] Backtracking in .NET regular expressions https://learn.microsoft.com/en-us/dotnet/standard/base-types/backtracking-in-regular-expressions
- [50] Secure Coding Guidelines | Mass Assignment https://learn.securecodewarrior.com/secure-coding-guidelines/mass-assignment
- [51] How to prevent mass assignment in ASP.NET Core https://softdevpractice.com/posts/asp-net-core-how-to-prevent-mass-assignment-attacks/
- [52] Mass Assignment - OWASP Cheat Sheet Series https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html
- [53] What is mass assignment? | Tutorial & examples https://learn.snyk.io/lesson/mass-assignment/
- [54] Protect complex object against Mass Assignment in ASP. ... https://stackoverflow.com/questions/75596677/protect-complex-object-against-mass-assignment-in-asp-net-mvc-using-c-sharp
- [55] CA2351: Ensure DataSet.ReadXml()'s input is trusted https://learn.microsoft.com/en-us/dotnet/fundamentals/code-analysis/quality-rules/ca2351
- [56] XML Denial of Service Attacks and Defenses https://learn.microsoft.com/en-us/archive/msdn-magazine/2009/november/xml-denial-of-service-attacks-and-defenses
- [57] How to protect against XML vulnerabilities in .NET https://www.meziantou.net/how-to-protect-against-xml-vulnerabilities-in-dotnet.htm
- [58] XEE attack (billion laughs attack) https://pvs-studio.com/en/blog/terms/6545/
