# Deep Research — Server-Side Vulnerabilities & Dangerous Code Patterns in Node.js

## Remote Code Execution (RCE)

**Bad Pattern 1: Using eval() with user input**
```javascript
app.get('/calc', (req, res) => {
  const result = eval(req.query.expr);
  res.send(result.toString());
});
```
**Explanation**: eval() executes any JavaScript code passed to it, allowing attackers to run arbitrary commands on the server[1][2].

**Bad Pattern 2: Using child_process.exec() with string concatenation**
```javascript
const { exec } = require('child_process');
app.post('/ping', (req, res) => {
  exec(`ping -c 4 ${req.body.host}`, (err, stdout) => {
    res.send(stdout);
  });
});
```
**Explanation**: Direct string concatenation in exec() allows command injection through shell metacharacters[3][4].

**Bad Pattern 3: Using vm.runInNewContext() with user input**
```javascript
const vm = require('vm');
app.post('/code', (req, res) => {
  const result = vm.runInNewContext(req.body.code, {});
  res.json({ result });
});
```
**Explanation**: VM module can be escaped using this.constructor.constructor to access Node.js globals and execute system commands[5][6].

## SQL Injection (SQLi)

**Bad Pattern 1: String interpolation in raw SQL queries**
```javascript
const query = `SELECT * FROM users WHERE id = ${req.params.id}`;
db.query(query, (err, results) => {
  res.json(results);
});
```
**Explanation**: Direct string interpolation bypasses parameterization, allowing SQL manipulation through crafted input[7][8].

**Bad Pattern 2: Using Sequelize.query() with concatenation**
```javascript
const userInput = req.query.name;
const query = `SELECT * FROM users WHERE name = '${userInput}'`;
sequelize.query(query, { type: sequelize.QueryTypes.SELECT });
```
**Explanation**: Raw queries in ORMs without parameterization remain vulnerable to SQL injection despite using modern frameworks[7][8].

**Bad Pattern 3: Dynamic query building without sanitization**
```javascript
let whereClause = "WHERE 1=1";
if (req.query.status) {
  whereClause += ` AND status = '${req.query.status}'`;
}
const query = `SELECT * FROM orders ${whereClause}`;
```
**Explanation**: Building dynamic SQL by string concatenation creates injection points that bypass ORM protections[9][10].

## Server-Side Request Forgery (SSRF)

**Bad Pattern 1: Using fetch() with user-provided URLs**
```javascript
app.post('/fetch-url', async (req, res) => {
  const response = await fetch(req.body.url);
  const data = await response.text();
  res.send(data);
});
```
**Explanation**: Unvalidated URL fetching allows attackers to access internal services and bypass firewalls[11][12].

**Bad Pattern 2: Using request library without URL validation**
```javascript
const request = require('request');
app.get('/proxy', (req, res) => {
  request(req.query.url, (err, response, body) => {
    res.send(body);
  });
});
```
**Explanation**: Direct URL proxying enables internal network scanning and sensitive file disclosure[13][14].

**Bad Pattern 3: HTTP client with insufficient URL filtering**
```javascript
const axios = require('axios');
app.post('/webhook', async (req, res) => {
  const response = await axios.get(req.body.callbackUrl);
  res.json(response.data);
});
```
**Explanation**: Simple URL filtering can be bypassed using localhost variations, IP encoding, and redirect chains[12][13].

## Path Traversal / Directory Traversal

**Bad Pattern 1: Using fs.readFile() with user input**
```javascript
const fs = require('fs');
app.get('/file', (req, res) => {
  fs.readFile(`./uploads/${req.query.filename}`, 'utf8', (err, data) => {
    res.send(data);
  });
});
```
**Explanation**: Unsanitized file paths allow attackers to read arbitrary files using ../../../ sequences[15][16].

**Bad Pattern 2: Path.join() without validation**
```javascript
const path = require('path');
app.get('/download', (req, res) => {
  const filepath = path.join(__dirname, 'files', req.params.file);
  res.sendFile(filepath);
});
```
**Explanation**: path.join() doesn't prevent traversal attacks; attackers can still use ../ to escape the intended directory[17][18].

**Bad Pattern 3: Express.static() misconfiguration**
```javascript
app.use('/files', express.static(req.query.directory));
```
**Explanation**: Dynamic static directory serving based on user input exposes the entire filesystem structure[17][19].

## Prototype Pollution

**Bad Pattern 1: Unsafe Object.assign() with user data**
```javascript
app.post('/config', (req, res) => {
  const config = {};
  Object.assign(config, req.body);
  res.json(config);
});
```
**Explanation**: Object.assign() copies __proto__ properties, allowing attackers to pollute the Object prototype[20][21].

**Bad Pattern 2: JSON.parse() with recursive merge**
```javascript
function merge(target, source) {
  for (let key in source) {
    if (typeof source[key] === 'object') {
      target[key] = merge(target[key] || {}, source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}
const payload = JSON.parse(req.body.data);
merge(appConfig, payload);
```
**Explanation**: Recursive merging without prototype checking allows __proto__ manipulation to pollute global object properties[22][23].

**Bad Pattern 3: Lodash merge with untrusted input**
```javascript
const _ = require('lodash');
app.post('/update', (req, res) => {
  _.merge(userPreferences, req.body);
  res.json({ success: true });
});
```
**Explanation**: Lodash merge functions are vulnerable to prototype pollution through specially crafted payloads containing __proto__ keys[22][24].

## Server-Side Template Injection (SSTI)

**Bad Pattern 1: EJS render with user input**
```javascript
const ejs = require('ejs');
app.post('/render', (req, res) => {
  const template = `<h1>Hello ${req.body.name}</h1>`;
  const html = ejs.render(template);
  res.send(html);
});
```
**Explanation**: Direct template compilation with user data allows JavaScript execution through EJS syntax injection[25][26].

**Bad Pattern 2: Handlebars compile with user templates**
```javascript
const handlebars = require('handlebars');
app.post('/template', (req, res) => {
  const template = handlebars.compile(req.body.template);
  const result = template(req.body.data);
  res.send(result);
});
```
**Explanation**: Compiling user-provided templates enables JavaScript code execution through Handlebars expressions[27][28].

**Bad Pattern 3: Mustache render with dynamic templates**
```javascript
const mustache = require('mustache');
app.get('/page', (req, res) => {
  const template = `Welcome {{${req.query.field}}}`;
  const rendered = mustache.render(template, userData);
  res.send(rendered);
});
```
**Explanation**: Dynamic template construction allows injection of malicious template syntax leading to code execution[28][29].

## Regular Expression Denial of Service (ReDoS)

**Bad Pattern 1: Vulnerable email validation regex**
```javascript
const emailRegex = /^([a-zA-Z0-9])(([\\-.]|[_]+)?([a-zA-Z0-9]+))*(@){1}[a-z0-9]+[.]{1}(([a-z]{2,3})|([a-z]{2,3}[.]{1}[a-z]{2,3}))$/;
app.post('/validate', (req, res) => {
  const isValid = emailRegex.test(req.body.email);
  res.json({ valid: isValid });
});
```
**Explanation**: Nested quantifiers in regex cause exponential backtracking when processing malicious input[30][31].

**Bad Pattern 2: URL validation with catastrophic backtracking**
```javascript
const urlRegex = /^https?:\/\/([\w\-]+\.)+[\w\-]+(\/[\w\-._~:/?#[\]@!$&'()*+,;=]*)?$/;
app.get('/check-url', (req, res) => {
  const valid = urlRegex.test(req.query.url);
  res.json({ valid });
});
```
**Explanation**: Complex regex patterns with alternation and repetition can be exploited to consume excessive CPU resources[32][33].

**Bad Pattern 3: User input in RegExp constructor**
```javascript
app.post('/search', (req, res) => {
  const pattern = new RegExp(req.body.pattern);
  const results = data.filter(item => pattern.test(item.name));
  res.json(results);
});
```
**Explanation**: User-controlled regex patterns can contain malicious expressions designed to cause denial of service[32][34].

## Insecure Deserialization

**Bad Pattern 1: node-serialize unserialize() with user data**
```javascript
const serialize = require('node-serialize');
app.post('/session', (req, res) => {
  const session = serialize.unserialize(req.body.session);
  res.json(session);
});
```
**Explanation**: node-serialize deserializes functions including IIFEs, allowing immediate code execution upon deserialization[35][36].

**Bad Pattern 2: eval() on serialized data**
```javascript
app.post('/restore', (req, res) => {
  const data = eval(`(${req.body.serializedData})`);
  res.json(data);
});
```
**Explanation**: Using eval() to deserialize data enables arbitrary JavaScript code execution through crafted payloads[37][38].

**Bad Pattern 3: Function constructor deserialization**
```javascript
app.post('/execute', (req, res) => {
  const func = new Function('return ' + req.body.code);
  const result = func();
  res.json({ result });
});
```
**Explanation**: Function constructor creates executable code from strings, providing direct code execution capability[37][39].

## XML External Entity (XXE) Injection

**Bad Pattern 1: libxml2 with entity processing enabled**
```javascript
const libxml = require('libxmljs');
app.post('/xml', (req, res) => {
  const doc = libxml.parseXml(req.body.xml, { noent: true });
  res.send(doc.toString());
});
```
**Explanation**: Enabling entity processing (noent: true) allows external entity resolution, leading to file disclosure and SSRF[40][41].

**Bad Pattern 2: xml2js without entity protection**
```javascript
const xml2js = require('xml2js');
app.post('/parse', (req, res) => {
  xml2js.parseString(req.body.xml, { 
    explicitCharkey: true,
    resolveEntity: true 
  }, (err, result) => {
    res.json(result);
  });
});
```
**Explanation**: Enabling entity resolution in XML parsers allows attackers to read local files and perform SSRF attacks[42][43].

**Bad Pattern 3: Custom XML parser without validation**
```javascript
const parseXML = (xmlString) => {
  return new DOMParser().parseFromString(xmlString, 'text/xml');
};
app.post('/process', (req, res) => {
  const doc = parseXML(req.body.xml);
  res.send(doc.documentElement.textContent);
});
```
**Explanation**: Custom XML parsing without entity restriction enables XXE attacks through malicious DTD declarations[41][44].

## Authentication Bypass

**Bad Pattern 1: JWT verification with decode() instead of verify()**
```javascript
const jwt = require('jsonwebtoken');
app.use('/protected', (req, res, next) => {
  const token = req.headers.authorization;
  const decoded = jwt.decode(token);
  req.user = decoded;
  next();
});
```
**Explanation**: Using decode() instead of verify() bypasses signature validation, allowing token manipulation[45][46].

**Bad Pattern 2: Accepting "none" algorithm JWTs**
```javascript
app.use('/api', (req, res, next) => {
  const token = req.headers.authorization;
  jwt.verify(token, null, { algorithms: ['none', 'HS256'] }, (err, decoded) => {
    req.user = decoded;
    next();
  });
});
```
**Explanation**: Accepting "none" algorithm allows unsigned tokens, completely bypassing authentication[45][47].

**Bad Pattern 3: Timing-vulnerable authentication**
```javascript
app.post('/login', (req, res) => {
  const user = users.find(u => u.username === req.body.username);
  if (!user) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  if (user.password === req.body.password) {
    res.json({ token: generateToken(user) });
  } else {
    res.status(401).json({ error: 'Invalid credentials' });
  }
});
```
**Explanation**: Different execution paths leak information about username existence through timing differences[48][49].

## Cross-Site Request Forgery (CSRF)

**Bad Pattern 1: State-changing operations without CSRF protection**
```javascript
app.post('/transfer', (req, res) => {
  const { amount, recipient } = req.body;
  transferMoney(req.session.userId, recipient, amount);
  res.json({ success: true });
});
```
**Explanation**: State-changing operations relying solely on session cookies are vulnerable to CSRF attacks[50][51].

**Bad Pattern 2: GET requests for sensitive operations**
```javascript
app.get('/delete-account', (req, res) => {
  deleteUser(req.session.userId);
  res.redirect('/goodbye');
});
```
**Explanation**: Using GET for destructive operations enables CSRF through simple image tags or links[52][53].

**Bad Pattern 3: Missing SameSite cookie attribute**
```javascript
app.use(session({
  secret: 'secret',
  cookie: { 
    httpOnly: true,
    secure: true
    // Missing sameSite: 'strict'
  }
}));
```
**Explanation**: Cookies without SameSite protection are sent with cross-site requests, enabling CSRF attacks[51][54].

## Race Conditions

**Bad Pattern 1: Non-atomic check-then-act operations**
```javascript
app.post('/withdraw', async (req, res) => {
  const balance = await getBalance(req.user.id);
  if (balance >= req.body.amount) {
    await updateBalance(req.user.id, balance - req.body.amount);
    res.json({ success: true });
  }
});
```
**Explanation**: Separate read and write operations create race conditions allowing double-spending attacks[55][56].

**Bad Pattern 2: Async operations on shared state**
```javascript
let counter = 0;
app.get('/increment', async (req, res) => {
  await someAsyncOperation();
  counter++;
  res.json({ counter });
});
```
**Explanation**: Concurrent modifications to shared variables without synchronization lead to inconsistent state[57][58].

**Bad Pattern 3: Database operations without transactions**
```javascript
app.post('/transfer', async (req, res) => {
  await debitAccount(req.body.from, req.body.amount);
  await creditAccount(req.body.to, req.body.amount);
  res.json({ success: true });
});
```
**Explanation**: Non-transactional database operations can result in partial updates during concurrent access[55][59].

## Insecure Randomness

**Bad Pattern 1: Using Math.random() for security tokens**
```javascript
app.post('/reset-password', (req, res) => {
  const token = Math.floor(Math.random() * 1000000).toString();
  saveResetToken(req.body.email, token);
  res.json({ token });
});
```
**Explanation**: Math.random() is predictable and unsuitable for security-sensitive operations like token generation[60][61].

**Bad Pattern 2: Weak session ID generation**
```javascript
app.use(session({
  genid: () => {
    return Date.now().toString() + Math.random().toString(36);
  }
}));
```
**Explanation**: Combining predictable values with weak randomness creates guessable session identifiers[62][63].

**Bad Pattern 3: Predictable UUID generation**
```javascript
const { v1: uuidv1 } = require('uuid');
app.post('/create-user', (req, res) => {
  const userId = uuidv1(); // Uses timestamp + MAC address
  createUser(userId, req.body);
  res.json({ userId });
});
```
**Explanation**: UUID v1 uses predictable components (timestamp, MAC address) making IDs guessable[63][64].

## Timing Attacks

**Bad Pattern 1: Variable-time string comparison**
```javascript
app.post('/verify', (req, res) => {
  if (req.body.token === secretToken) {
    res.json({ valid: true });
  } else {
    res.json({ valid: false });
  }
});
```
**Explanation**: Standard string comparison fails fast on first mismatch, leaking information about correct prefixes[48][65].

**Bad Pattern 2: Early exit on user existence check**
```javascript
app.post('/login', async (req, res) => {
  const user = await User.findOne({ email: req.body.email });
  if (!user) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  const valid = await bcrypt.compare(req.body.password, user.hash);
  res.json({ valid });
});
```
**Explanation**: Different execution paths for existing vs. non-existing users create timing side channels[49][66].

**Bad Pattern 3: Conditional hashing based on input**
```javascript
app.post('/auth', (req, res) => {
  if (req.body.password.length < 8) {
    return res.status(400).json({ error: 'Password too short' });
  }
  const hash = bcrypt.hashSync(req.body.password, 10);
  res.json({ hash });
});
```
**Explanation**: Skipping expensive operations for invalid input creates measurable timing differences[48][67].

# Sources:
- [1] JavaScript eval security best practices - Codiga https://www.codiga.io/blog/javascript-eval-best-practices/
- [2] 5 ways to prevent code injection in JavaScript and Node.js - Snyk https://snyk.io/blog/5-ways-to-prevent-code-injection-in-javascript-and-node-js/
- [3] aadityapurani/NodeJS-Red-Team-Cheat-Sheet - GitHub https://github.com/aadityapurani/NodeJS-Red-Team-Cheat-Sheet
- [4] Preventing Command Injection Attacks in Node.js Apps - Auth0 https://auth0.com/blog/preventing-command-injection-attacks-in-node-js-apps/
- [5] The security concerns of a JavaScript sandbox with the Node.js VM ... https://snyk.io/blog/security-concerns-javascript-sandbox-node-js-vm-module/
- [6] The unsecure node vm module - Eslam Salem http://eslam.io/posts/unsecure-node-vm/
- [7] Sequelize ORM npm library found vulnerable to SQL Injection attacks https://snyk.io/blog/sequelize-orm-npm-library-found-vulnerable-to-sql-injection-attacks/
- [8] SQL Injection in the Age of ORM: Risks, Mitigations, and Best Practices https://afine.com/sql-injection-in-the-age-of-orm-risks-mitigations-and-best-practices/
- [9] Node.js SQL Injection Guide: Examples and Prevention - StackHawk https://www.stackhawk.com/blog/node-js-sql-injection-guide-examples-and-prevention/
- [10] 10 Best SQL injection attack mitigation in Node.js - Cyber Rely https://www.cybersrely.com/sql-injection-attack-mitigation-in-node-js/
- [11] OWASP Top 10 API Security Risks – 2023 https://owasp.org/API-Security/editions/2023/en/0x11-t10/
- [12] Vulnerable NPM security module allowed attackers to bypass SSRF ... https://portswigger.net/daily-swig/vulnerable-npm-security-module-allowed-attackers-to-bypass-ssrf-defenses
- [13] An Introduction to SSRF Bypasses and Denylist Failures https://www.nodejs-security.com/blog/introduction-to-ssrf-bypasses-and-denylist-failures
- [14] OWASP Top 10 Server-Side Request Forgery Explained https://www.securityjourney.com/post/owasp-top-10-server-side-request-forgery-explained
- [15] Node.js API Security Vulnerabilities with Path Traversal in files ... https://www.nodejs-security.com/blog/nodejs-api-security-vulnerabilities-path-traversal-files-bucket-server
- [16] What is path traversal, and how to prevent it? | Web Security Academy https://portswigger.net/web-security/file-path-traversal
- [17] does nodejs prevent directory/path traversal by default? https://stackoverflow.com/questions/65860214/does-nodejs-prevent-directory-path-traversal-by-default
- [18] NodeJS Path Traversal Vulnerability Scanner https://www.nodejs-security.com/blog/nodejs-path-traversal-vulnerability-scanner
- [19] Node.js Path Traversal: Examples & Mitigation - StackHawk https://www.stackhawk.com/blog/node-js-path-traversal-guide-examples-and-prevention/
- [20] What is prototype pollution? | Web Security Academy - PortSwigger https://portswigger.net/web-security/prototype-pollution
- [21] Understanding and Preventing Prototype Pollution in Node.js https://www.nodejs-security.com/blog/understanding-and-preventing-prototype-pollution-in-nodejs
- [22] Prototype Pollution in deep-parse-json | CVE-2022-42743 | Snyk https://security.snyk.io/vuln/SNYK-JS-DEEPPARSEJSON-3104597
- [23] Prevent Prototype Manipulation | Learn Node.js Security https://www.nodejs-security.com/learn/nodejs-runtime-security/prevent-prototype-manipulation
- [24] Server-side prototype pollution | Web Security Academy - PortSwigger https://portswigger.net/web-security/prototype-pollution/server-side
- [25] ejs template injection vulnerability · CVE-2022-29078 - GitHub https://github.com/advisories/GHSA-phwq-j96m-2c2q
- [26] Server-Side Template Injection (Node.js EJS) - Invicti https://www.invicti.com/web-vulnerability-scanner/vulnerabilities/server-side-template-injection-nodejs-ejs/
- [27] Prototype Pollution in handlebars | CVE-2021-23383 | Snyk https://security.snyk.io/vuln/SNYK-JS-HANDLEBARS-1279029
- [28] Server-Side Template Injection (SSTI): Advanced Exploitation Guide https://www.intigriti.com/researchers/blog/hacking-tools/exploiting-server-side-template-injection-ssti
- [29] Hacking Websites: NodeJS Server-Side Template Injection - YouTube https://www.youtube.com/watch?v=cl94KRdJRxw
- [30] Unpatched regex bug leaves Node.js apps open to ReDoS attacks https://portswigger.net/daily-swig/unpatched-regex-bug-leaves-node-js-apps-open-to-redos-attacks
- [31] How to protect against regex denial-of-service (ReDoS) attacks https://blog.logrocket.com/protect-against-regex-denial-of-service-redos-attacks/
- [32] eslint-plugin-security/docs/regular-expression-dos-and-node.md at ... https://github.com/eslint-community/eslint-plugin-security/blob/main/docs/regular-expression-dos-and-node.md
- [33] Regular expression Denial of Service - ReDoS - OWASP Foundation https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS
- [34] Regular Expression in parse Leads to ReDoS Vulnerability Due to ... https://github.com/octokit/endpoint.js/security/advisories/GHSA-x4c5-c7rf-jjgv
- [35] Node JS Deserialization Exploitation https://blog.certcube.com/node-js-deserialization-exploitation-and-defence/
- [36] Preventing insecure deserialization in Node.js - Snyk https://snyk.io/blog/preventing-insecure-deserialization-node-js/
- [37] Insecure Deserialization - | Cobalt https://docs.cobalt.io/bestpractices/insecure-deserialization/
- [38] node-serialize Insecure Deserialization - Web Application ... - Invicti https://www.invicti.com/web-application-vulnerabilities/node-serialize-insecure-deserialization
- [39] node-serialize Insecure Deserialization - Vulnerabilities - Acunetix https://www.acunetix.com/vulnerabilities/web/node-serialize-insecure-deserialization/
- [40] XML External Entity (XXE) Processing - GeeksforGeeks https://www.geeksforgeeks.org/ethical-hacking/xml-external-entity-xxe-processing/
- [41] NodeJS XML External Entities (XXE) Guide: Examples and Prevention https://www.stackhawk.com/blog/nodejs-xml-external-entities-xxe-guide-examples-and-prevention/
- [42] Angular XML External Entities (XXE) Guide: Examples and Prevention https://www.stackhawk.com/blog/angular-xml-external-entities-xxe-guide-examples-and-prevention/
- [43] XXE - Mobb User Docs https://docs.mobb.ai/mobb-user-docs/fixing-guides/xxe-fix-guide
- [44] XML External Entity (XXE) Injection in libxml2 | CVE-2024-40896 https://security.snyk.io/vuln/SNYK-UNMANAGED-LIBXML2-8549367
- [45] Decoding JWT Vulnerabilities: A Deep Dive Into JWT Security Risks ... https://www.redsentry.com/blog/decoding-jwt-vulnerabilities-a-deep-dive-into-jwt-security-risks-and-mitigation
- [46] How to Avoid JWT Security Mistakes in Node.js https://www.nodejs-security.com/blog/how-avoid-jwt-security-mistakes-nodejs
- [47] JWT attacks | Web Security Academy - PortSwigger https://portswigger.net/web-security/jwt
- [48] Timing Attacks in Node.js - DEV Community https://dev.to/silentwatcher_95/timing-attacks-in-nodejs-4pmb
- [49] Timing Attack using bcrypt.js : r/node - Reddit https://www.reddit.com/r/node/comments/16taqf1/timing_attack_using_bcryptjs/
- [50] Cross-Site Request Forgery Prevention - OWASP Cheat Sheet Series https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html
- [51] CSRF Attack | Tutorial & Examples - Snyk Learn https://learn.snyk.io/lesson/csrf-attack/
- [52] Cross-site request forgery (CSRF) - Security - MDN - Mozilla https://developer.mozilla.org/en-US/docs/Web/Security/Attacks/CSRF
- [53] Prevent Cross-Site Request Forgery (CSRF) Attacks - Auth0 https://auth0.com/blog/cross-site-request-forgery-csrf/
- [54] Node.js CSRF Protection Guide: Examples and How to Enable It https://www.stackhawk.com/blog/node-js-csrf-protection-guide-examples-and-how-to-enable-it/
- [55] How to avoid race condition with Async/Await Database operations https://www.reddit.com/r/node/comments/bgfks8/how_to_avoid_race_condition_with_asyncawait/
- [56] How to fix a Race Condition in an Async Architecture? https://www.geeksforgeeks.org/system-design/how-to-fix-a-race-condition-in-an-async-architecture/
- [57] Can node.js code result in race conditions? - Stack Overflow https://stackoverflow.com/questions/21438207/can-node-js-code-result-in-race-conditions
- [58] The Ultimate Guide to Race Condition Testing in Web Applications https://momentic.ai/resources/the-ultimate-guide-to-race-condition-testing-in-web-applications
- [59] A Survey of Race Condition Vulnerability Detectors - arXiv https://arxiv.org/html/2312.14479v1
- [60] Avoid Math.random() in Node.js: Use Secure Crypto Instead - LinkedIn https://www.linkedin.com/pulse/why-you-should-avoid-mathrandom-nodejs-use-randomness-upadhyay-1dflf
- [61] Math.random() Exploit: PRNG Means Pseudosecurity - Black Duck https://www.blackduck.com/blog/pseudorandom-number-generation.html
- [62] Insecure Randomness - Mobb User Docs https://docs.mobb.ai/mobb-user-docs/fixing-guides/insecure-randomness-fix-guide
- [63] What is insecure randomness? | Tutorial & examples - Snyk Learn https://learn.snyk.io/lesson/insecure-randomness/
- [64] Insecure Use of Cryptography - GuardRails https://docs.guardrails.io/docs/vulnerabilities/javascript/insecure_use_of_crypto
- [65] Is bcrypt.compare vulnerable to timing attack - Stack Overflow https://stackoverflow.com/questions/35620979/is-bcrypt-compare-vulnerable-to-timing-attack
- [66] Using Node.js event loop for timing attacks - Snyk https://snyk.io/blog/node-js-timing-attack-ccc-ctf/
- [67] Poor Express Authentication Patterns in Node.js and How to Avoid ... https://lirantal.com/blog/poor-express-authentication-patterns-nodejs
