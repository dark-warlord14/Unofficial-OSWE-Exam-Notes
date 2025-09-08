# **Server-Side Vulnerabilities & Dangerous Code Patterns in Java**

## **Remote Code Execution (RCE)**

**Bad Pattern 1: Runtime.exec() with user input**  
```java
String userInput = request.getParameter("cmd");
String cmd = "ls -la " + userInput;
Runtime.getRuntime().exec(cmd);
```
Explanation: Direct concatenation allows command injection through shell metacharacters like ";&|" enabling arbitrary command execution[1][2].

**Bad Pattern 2: ProcessBuilder with shell invocation**  
```java
String userFile = request.getParameter("file");
ProcessBuilder pb = new ProcessBuilder("bash", "-c", "cat " + userFile);
pb.start();
```
Explanation: Using shell with concatenated user input bypasses ProcessBuilder's argument separation, allowing command injection[3][4].

**Bad Pattern 3: Class.forName() with user input**  
```java
String className = request.getParameter("class");
Class<?> clazz = Class.forName("com.example." + className);
Object instance = clazz.newInstance();
```
Explanation: Loading arbitrary classes enables instantiation of dangerous classes that execute code in constructors or static blocks[5][6].

## **SQL Injection (SQLi)**

**Bad Pattern 1: Statement.executeQuery() with concatenation**  
```java
String userId = request.getParameter("id");
String query = "SELECT * FROM users WHERE id = " + userId;
Statement stmt = connection.createStatement();
ResultSet rs = stmt.executeQuery(query);
```
Explanation: String concatenation allows SQL code injection that can alter query logic and access unauthorized data[7][8].

**Bad Pattern 2: Statement.executeUpdate() with dynamic queries**  
```java
String username = request.getParameter("user");
String sql = "UPDATE users SET status='active' WHERE name='" + username + "'";
stmt.executeUpdate(sql);
```
Explanation: Concatenated parameters enable SQL injection that can modify unintended records or execute additional statements[9][10].

**Bad Pattern 3: CallableStatement with string building**  
```java
String param = request.getParameter("data");
String call = "{call getUserInfo('" + param + "')}";
CallableStatement cs = connection.prepareCall(call);
cs.execute();
```
Explanation: Building stored procedure calls with user input allows manipulation of procedure parameters and execution flow[11][12].

## **Server-Side Request Forgery (SSRF)**

**Bad Pattern 1: URLConnection.openConnection() with user URLs**  
```java
String url = request.getParameter("url");
URL obj = new URL(url);
HttpURLConnection con = (HttpURLConnection) obj.openConnection();
con.getInputStream();
```
Explanation: Unvalidated URLs enable access to internal services, cloud metadata endpoints, and bypassing firewall restrictions[13][14].

**Bad Pattern 2: HttpURLConnection without validation**  
```java
String targetUrl = request.getParameter("target");
HttpURLConnection connection = (HttpURLConnection) new URL(targetUrl).openConnection();
BufferedReader reader = new BufferedReader(new InputStreamReader(connection.getInputStream()));
```
Explanation: Direct connection to user-supplied URLs allows internal network scanning and accessing restricted services[15][16].

**Bad Pattern 3: URL constructor with external input**  
```java
String endpoint = request.getParameter("api");
URL apiUrl = new URL("http://internal-service:8080/" + endpoint);
URLConnection conn = apiUrl.openConnection();
```
Explanation: Constructing URLs with user input enables path manipulation to access unintended internal endpoints[17][18].

## **XML External Entity (XXE)**

**Bad Pattern 1: DocumentBuilderFactory without secure processing**  
```java
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
DocumentBuilder db = dbf.newDocumentBuilder();
Document doc = db.parse(userInputStream);
```
Explanation: Default XML parser configuration processes external entities enabling file disclosure and SSRF attacks[19][20].

**Bad Pattern 2: SAXParserFactory with default settings**  
```java
SAXParserFactory factory = SAXParserFactory.newInstance();
SAXParser parser = factory.newSAXParser();
parser.parse(xmlInput, new DefaultHandler());
```
Explanation: SAX parsers with external entity processing enabled allow XXE attacks to read local files and make network requests[21][22].

**Bad Pattern 3: XMLInputFactory without DTD restrictions**  
```java
XMLInputFactory factory = XMLInputFactory.newInstance();
XMLStreamReader reader = factory.createXMLStreamReader(inputStream);
```
Explanation: StAX parsers that support DTDs enable external entity injection for information disclosure and denial of service[21][23].

## **Insecure Deserialization**

**Bad Pattern 1: ObjectInputStream.readObject() on untrusted data**  
```java
ObjectInputStream ois = new ObjectInputStream(socket.getInputStream());
Object obj = ois.readObject();
MyClass data = (MyClass) obj;
```
Explanation: Deserializing untrusted data allows attackers to instantiate arbitrary classes and execute gadget chains for RCE[24][25].

**Bad Pattern 2: ObjectInputStream without class filtering**  
```java
FileInputStream fis = new FileInputStream(userFile);
ObjectInputStream ois = new ObjectInputStream(fis);
return ois.readObject();
```
Explanation: Reading serialized objects without validation enables exploitation of known gadget chains in common libraries[26][27].

**Bad Pattern 3: Custom readObject() method**  
```java
private void readObject(ObjectInputStream in) throws IOException {
    in.defaultReadObject();
    Runtime.getRuntime().exec(this.command);
}
```
Explanation: Custom deserialization methods can execute dangerous operations during object reconstruction[25][28].

## **Path Traversal**

**Bad Pattern 1: File constructor with user input**  
```java
String filename = request.getParameter("file");
File file = new File("/var/www/files/" + filename);
FileInputStream fis = new FileInputStream(file);
```
Explanation: Concatenating user input to file paths enables directory traversal using "../" sequences to access arbitrary files[29][30].

**Bad Pattern 2: FileInputStream without path validation**  
```java
String userPath = request.getParameter("path");
File targetFile = new File(userPath);
Files.copy(targetFile.toPath(), response.getOutputStream());
```
Explanation: Direct file access with user-controlled paths allows reading sensitive system files and application configuration[31][32].

**Bad Pattern 3: ServletContext.getResource() with user paths**  
```java
String resourcePath = request.getParameter("resource");
URL resource = getServletContext().getResource("/files/" + resourcePath);
InputStream is = resource.openStream();
```
Explanation: Resource access with unvalidated paths can expose application files and bypass intended access controls[33][34].

## **Unsafe Reflection**

**Bad Pattern 1: Class.forName() with user input**  
```java
String userClass = request.getParameter("type");
Class<?> clazz = Class.forName("com.example." + userClass);
Object instance = clazz.getDeclaredConstructor().newInstance();
```
Explanation: Loading classes based on user input enables instantiation of malicious classes that execute code during construction[35][36].

**Bad Pattern 2: Method.invoke() on user-specified methods**  
```java
String methodName = request.getParameter("method");
Method method = targetClass.getMethod(methodName);
method.invoke(instance, userArgs);
```
Explanation: Invoking methods determined by user input bypasses access controls and can execute unintended dangerous functionality[37][38].

**Bad Pattern 3: Constructor.newInstance() with external data**  
```java
String constructorClass = request.getParameter("constructor");
Class<?> clazz = Class.forName(constructorClass);
Constructor<?> constructor = clazz.getConstructor();
constructor.newInstance();
```
Explanation: Creating instances using user-controlled constructor selection can execute arbitrary code in constructors or static blocks[6][39].

## **LDAP Injection**

**Bad Pattern 1: DirContext.search() with string concatenation**  
```java
String user = request.getParameter("username");
String searchFilter = "(uid=" + user + ")";
NamingEnumeration results = dirContext.search(searchBase, searchFilter, searchControls);
```
Explanation: Building LDAP filters through concatenation allows filter manipulation to bypass authentication and access unauthorized data[40][41].

**Bad Pattern 2: InitialDirContext with unsanitized DN construction**  
```java
String userInput = request.getParameter("ou");
String dn = "ou=" + userInput + ",dc=example,dc=com";
context.createSubcontext(dn, attributes);
```
Explanation: Constructing distinguished names from user input enables LDAP injection to create unauthorized directory entries[40][42].

**Bad Pattern 3: SearchControls with user-controlled parameters**  
```java
String searchCriteria = request.getParameter("search");
String query = "(&(objectClass=person)(|" + searchCriteria + "))";
NamingEnumeration results = context.search(searchBase, query, controls);
```
Explanation: Embedding user input in complex LDAP filters allows attackers to modify search scope and extract sensitive directory information[40][43].

## **Server-Side Template Injection (SSTI)**

**Bad Pattern 1: Velocity template rendering with user input**  
```java
String userTemplate = request.getParameter("template");
VelocityEngine engine = new VelocityEngine();
StringWriter writer = new StringWriter();
engine.evaluate(context, writer, "userTemplate", userTemplate);
```
Explanation: Processing user-controlled template content enables arbitrary Java code execution through Velocity's expression language[44][45].

**Bad Pattern 2: Template.evaluate() with untrusted input**  
```java
String templateContent = request.getParameter("content");
Template template = Template.compile(templateContent);
template.evaluate(velocityContext);
```
Explanation: Compiling and evaluating user-supplied templates allows access to Java objects and methods for remote code execution[46][47].

**Bad Pattern 3: VelocityContext with exposed objects**  
```java
VelocityContext context = new VelocityContext();
context.put("request", request);
context.put("runtime", Runtime.getRuntime());
engine.evaluate(context, writer, "template", userInput);
```
Explanation: Exposing dangerous objects in template context enables attackers to invoke system commands and access sensitive resources[44][48].

# Sources:
- [1] `Runtime.exec()` call may be susceptible to injection attacks - JAVA ... https://deepsource.com/directory/java/issues/JAVA-A1057
- [2] Command injection prevention for Java - Semgrep https://semgrep.dev/docs/cheat-sheets/java-command-injection
- [3] Unveiling Command Injection Vulnerabilities in Java: Deep dive into ... https://infosecwriteups.com/- unveiling-command-injection-vulnerabilities-in-java-deep-dive-into-processbuilder-and-runtime-50d8e25d06ab
- [4] Command Injection in Java: Examples and Prevention - StackHawk https://www.stackhawk.com/blog/command-injection-java/
- [5] Code injection prevention for Java - Semgrep https://semgrep.dev/docs/cheat-sheets/java-code-injection
- [6] A Primer on Insecure Reflection Practices in Java and C# Applications https://www.sprocketsecurity.com/blog/- a-primer-on-insecure-reflection-practices-in-java-and-c-applications
- [7] Statement.executeQuery() and SQL injection - java - Stack Overflow https://stackoverflow.com/questions/31017584/statement-executequery-and-sql-injection
- [8] Vulnerable to SQL Injection? - java - Stack Overflow https://stackoverflow.com/questions/45525503/vulnerable-to-sql-injection
- [9] SQL Injection in Java and How to Easily Prevent it - DigitalOcean https://www.digitalocean.com/community/tutorials/sql-injection-in-java
- [10] What is a SQL Injection in Java? - Contrast Security https://www.contrastsecurity.com/developer/learn/sql-injection/java
- [11] CVE-2024-1597: SQL Injection Vulnerability in PostgreSQL JDBC ... https://www.sangfor.com/farsight-labs-threat-intelligence/cybersecurity/- cve-2024-1597-sql-injection-vulnerability
- [12] SQL Injection in java-postgresql-jdbc | CVE-2024-1597 | Snyk https://security.snyk.io/vuln/SNYK-ALPINE319-JAVAPOSTGRESQLJDBC-6516629
- [13] Server Side Request Forgery | Mobb User Docs https://docs.mobb.ai/mobb-user-docs/fixing-guides/ssrf-fix-guide
- [14] What is SSRF (server-side request forgery)? | Tutorial & examples https://learn.snyk.io/lesson/ssrf-server-side-request-forgery/
- [15] What is SSRF (Server-side request forgery)? Tutorial & Examples https://portswigger.net/web-security/ssrf
- [16] Server Side Request Forgery (SSRF) Attacks & How to Prevent Them https://brightsec.com/blog/ssrf-server-side-request-forgery/
- [17] How to Defend Against Server-Side Request Forgery - freeCodeCamp https://www.freecodecamp.org/news/defending-against-ssrf-attacks/
- [18] How to Protect URLs from SSRF Threats in Java - DZone https://dzone.com/articles/how-to-protect-urls-from-ssrf-threats-in-java
- [19] `DocumentBuilder` may be vulnerable to XXE attacks - JAVA-A1052 https://deepsource.com/directory/java/issues/JAVA-A1052
- [20] XML External Entity (XXE) Attacks and How to Avoid Them https://brightsec.com/blog/xxe-prevention/
- [21] XML External Entity Prevention - OWASP Cheat Sheet Series https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html
- [22] XML External entity prevention for Java - Semgrep https://semgrep.dev/docs/cheat-sheets/java-xxe
- [23] Unveiling Java Library Vulnerabilities | Kondukto https://kondukto.io/blog/unveiling-java-library-vulnerabilities-through-xxe-exploration
- [24] Deserialization of untrusted data - OWASP Foundation https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data
- [25] Java Deserialization Gadget Chains - K logix https://www.klogixsecurity.com/scorpion-labs-blog/gadget-chains
- [26] Deserialization - OWASP Cheat Sheet Series https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html
- [27] JDK approach to address deserialization vulnerability - Red Hat https://www.redhat.com/en/blog/jdk-approach-address-deserialization-vulnerability
- [28] What is a Java Deserialization Vulnerability? - Waratek https://waratek.com/blog/java-deserialization-vulnerability/
- [29] Path Traversal and Remediation in Java - System Weakness https://systemweakness.com/path-traversal-and-remediation-in-java-28a1edb45853
- [30] What is path traversal, and how to prevent it? | Web Security Academy https://portswigger.net/web-security/file-path-traversal
- [31] Potential path traversal vulnerability when using File class and its ... https://dev.to/arpanforgeek/- potential-path-traversal-vulnerability-when-using-file-class-and-its-solution-3n6e
- [32] Mitigating path traversal vulns in Java with Snyk Code https://snyk.io/blog/mitigating-path-traversal-java-snyk-code/
- [33] Exploiting path traversal vulnerabilities in Java web applications https://www.invicti.com/white-papers/- exploiting-path-traversal-vulnerabilities-java-web-applications-technical-paper/
- [34] Path Traversal | OWASP Foundation https://owasp.org/www-community/attacks/Path_Traversal
- [35] How to secure Class.forName("SimpleClass")? - java - Stack Overflow https://stackoverflow.com/questions/40992901/how-to-secure-class-fornamesimpleclass
- [36] SEC52-J. Do not expose methods that use reduced-security checks ... https://wiki.sei.cmu.edu/confluence/display/java/SEC52-J.+Do+not+expose+methods+that+use- +reduced-security+checks+to+untrusted+code
- [37] Unsafe use of Reflection - OWASP Foundation https://owasp.org/www-community/vulnerabilities/Unsafe_use_of_Reflection
- [38] Arbitrary code execution via Java reflection in IntegratedScripting https://github.com/CyclopsMC/IntegratedScripting/security/advisories/GHSA-2v5x-4823-hq77
- [39] Avoid user-generated class names for reflection - Datadog Docs https://docs.datadoghq.com/security/code_security/static_analysis/static_analysis_rules/- java-security/unsafe-reflection/
- [40] What Is LDAP Injection? - Types, Examples And How To Prevent It https://www.mend.io/blog/what-is-ldap-injection-types-examples-and-how-to-prevent-it/
- [41] LDAP injection - Java - Knowledge Base - Fluid Attacks https://help.fluidattacks.com/portal/en/kb/articles/criteria-fixes-java-107
- [42] Complete Guide to LDAP Injection: Types, Examples, and Prevention https://brightsec.com/blog/ldap-injection/
- [43] What is LDAP Injection | Examples & Prevention - Imperva https://www.imperva.com/learn/application-security/ldap-injection/
- [44] Testing Velocity Server-Side Template Injection - Antgarsil Pages https://antgarsil.github.io/posts/velocity/
- [45] A Pentester's Guide to Server Side Template Injection (SSTI) - Cobalt https://www.cobalt.io/blog/a-pentesters-guide-to-server-side-template-injection-ssti
- [46] Server-Side Template Injection Guide and Prevention Tips https://abnormal.ai/blog/server-side-template-injection
- [47] Code Execution via SSTI (Java Velocity) - Invicti https://www.invicti.com/web-vulnerability-scanner/vulnerabilities/code-execution-via-ssti-java-velocity/
- [48] Server-Side Template Injection | PortSwigger Research https://portswigger.net/research/server-side-template-injection
