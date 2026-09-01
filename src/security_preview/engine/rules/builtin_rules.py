"""Built-in SAST rules ported from ``security_auditor/security_checker.py``.

Each :class:`Rule` carries everything needed to build a
:class:`security_preview.models.Finding`: severity, confidence, category, CWE and
split remediation text. Patterns are the originals from the Security Auditor,
re-compiled here. High-signal rules (SQLi, command injection, deserialization)
are marked ``windowed`` so the scanner matches them against a sliding multi-line
window instead of a single line.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from ...models import Confidence, RiskLevel

# Sliding window (in lines) used for ``windowed`` rules.
MATCH_WINDOW = 3


@dataclass(frozen=True)
class Rule:
    rule_id: str
    name: str
    pattern: re.Pattern[str]
    description: str
    severity: RiskLevel
    confidence: Confidence
    category: str
    cwe_id: str
    languages: frozenset[str]
    remediation_vulnerable: str
    remediation_secure: str
    windowed: bool = False
    false_positive_patterns: tuple[re.Pattern[str], ...] = field(default_factory=tuple)


def _compile(pattern: str, *, windowed: bool) -> re.Pattern[str]:
    flags = re.IGNORECASE
    # windowed rules match across newlines so cross-line concatenation is caught
    flags |= re.DOTALL if windowed else re.MULTILINE
    return re.compile(pattern, flags)


def _rule(
    rule_id: str,
    name: str,
    pattern: str,
    description: str,
    severity: RiskLevel,
    confidence: Confidence,
    category: str,
    cwe_id: str,
    languages: list[str],
    remediation_vulnerable: str,
    remediation_secure: str,
    *,
    windowed: bool = False,
    false_positive_patterns: list[str] | None = None,
) -> Rule:
    return Rule(
        rule_id=rule_id,
        name=name,
        pattern=_compile(pattern, windowed=windowed),
        description=description,
        severity=severity,
        confidence=confidence,
        category=category,
        cwe_id=cwe_id,
        languages=frozenset(languages),
        remediation_vulnerable=remediation_vulnerable.strip(),
        remediation_secure=remediation_secure.strip(),
        windowed=windowed,
        false_positive_patterns=tuple(
            re.compile(fp, re.IGNORECASE) for fp in (false_positive_patterns or [])
        ),
    )


_WEB = [".js", ".ts", ".jsx", ".tsx"]

RULES: list[Rule] = [
    # ---------------------------------------------------------------- Injection
    _rule(
        "sast.sql-injection",
        "SQL Injection",
        r"""(?:execute|cursor\.execute|query|raw|rawQuery|executeQuery)\s*\(\s*[f"'].*?%s.*?['"]\s*%|(?:execute|cursor\.execute)\s*\(\s*[f"'].*?\{.*?\}.*?['"]|(?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER).*?['"]\s*\+\s*|f['"]\s*(?:SELECT|INSERT|UPDATE|DELETE).*?\{""",
        "User input may be concatenated into a SQL query, letting an attacker "
        "alter the statement and reach or modify arbitrary data.",
        RiskLevel.CRITICAL,
        Confidence.HIGH,
        "Injection",
        "CWE-89",
        [".py", ".java", ".php", ".js", ".ts", ".rb", ".go", ".cs"],
        'cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")',
        'cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))',
        windowed=True,
        false_positive_patterns=[r"#.*SQL", r"//.*SQL", r"/\*.*SQL"],
    ),
    _rule(
        "sast.command-injection",
        "Command Injection",
        r"""(?:os\.system|os\.popen|subprocess\.call|subprocess\.run|subprocess\.Popen|exec|eval|Runtime\.getRuntime\(\)\.exec|shell_exec|system|passthru|popen)\s*\([^)]*(?:\+|%|\.format|\{|\$)""",
        "User input may be passed to a system shell, allowing arbitrary command "
        "execution on the host.",
        RiskLevel.CRITICAL,
        Confidence.HIGH,
        "Injection",
        "CWE-78",
        [".py", ".java", ".php", ".js", ".ts", ".rb", ".go", ".sh"],
        'os.system(f"ping {user_input}")',
        'subprocess.run(["ping", user_input], shell=False)',
        windowed=True,
    ),
    _rule(
        "sast.xss",
        "Cross-Site Scripting (XSS)",
        r"""(?:innerHTML|outerHTML|document\.write|\.html\(|v-html|dangerouslySetInnerHTML|\[innerHTML\])\s*=?\s*(?:[^;]*(?:\+|`|\$\{))""",
        "Untrusted data is written into the DOM without encoding, allowing script "
        "injection in the victim's browser.",
        RiskLevel.HIGH,
        Confidence.MEDIUM,
        "Injection",
        "CWE-79",
        [".js", ".ts", ".jsx", ".tsx", ".html", ".php"],
        "element.innerHTML = userInput;",
        "element.textContent = userInput;  // or DOMPurify.sanitize(...)",
    ),
    _rule(
        "sast.path-traversal",
        "Path Traversal",
        r"""(?:open|read|write|file_get_contents|file_put_contents|include|require|fopen|readFile|writeFile|createReadStream)\s*\([^)]*(?:\+|`|\$\{|\.\./)""",
        "User input is used to build a filesystem path, letting an attacker read "
        "or write files outside the intended directory.",
        RiskLevel.HIGH,
        Confidence.MEDIUM,
        "Injection",
        "CWE-22",
        [".py", ".java", ".php", ".js", ".ts", ".rb", ".go"],
        'open(f"/uploads/{filename}")',
        "safe = os.path.normpath(filename)\n"
        "full = os.path.join(UPLOAD_DIR, safe)\n"
        "if not full.startswith(UPLOAD_DIR):\n"
        '    raise ValueError("path traversal")',
    ),
    _rule(
        "sast.ldap-injection",
        "LDAP Injection",
        r"""(?:ldap_search|ldap_bind|search_s|search_ext_s)\s*\([^)]*(?:\+|%|\.format|\{)""",
        "User input is placed into an LDAP filter without escaping.",
        RiskLevel.HIGH,
        Confidence.MEDIUM,
        "Injection",
        "CWE-90",
        [".py", ".java", ".php", ".cs"],
        'ldap.search_s(base, scope, f"(uid={username})")',
        "from ldap3.utils.conv import escape_filter_chars\n"
        'ldap.search_s(base, scope, f"(uid={escape_filter_chars(username)})")',
    ),
    _rule(
        "sast.prototype-pollution",
        "Prototype Pollution",
        r"""(?:Object\.assign|_\.merge|_\.extend|_\.defaults|jQuery\.extend|angular\.(?:merge|extend))\s*\([^,]*,\s*(?:req\.|request\.|params\.|body\.|input)|\[['"]__proto__['"]\]|\[['"]constructor['"]\]\.prototype""",
        "Merging user-controlled objects can write to ``Object.prototype`` and "
        "corrupt application-wide state.",
        RiskLevel.HIGH,
        Confidence.MEDIUM,
        "Injection",
        "CWE-1321",
        [".js", ".ts"],
        "Object.assign(target, req.body);",
        "const allowed = ['name', 'email'];\n"
        "for (const k of allowed) if (k in input) safe[k] = input[k];",
    ),
    _rule(
        "sast.xxe",
        "XML External Entity (XXE)",
        r"""(?:xml\.etree|lxml|xml\.dom|xml\.sax|XMLReader|DocumentBuilder|SAXParser|XMLParser).*(?:parse|read|load)|<!ENTITY|SYSTEM\s+['"]|resolve_entities\s*=\s*True""",
        "An XML parser is used without disabling external entity resolution, "
        "enabling file disclosure and SSRF.",
        RiskLevel.HIGH,
        Confidence.MEDIUM,
        "Injection",
        "CWE-611",
        [".py", ".java", ".php", ".cs", ".rb"],
        "tree = xml.dom.minidom.parse(user_file)",
        "from defusedxml.ElementTree import parse\n"
        "tree = parse(user_file)",
    ),
    # ------------------------------------------------------------------- Secrets
    _rule(
        "sast.hardcoded-credentials",
        "Hardcoded Credentials",
        r"""(?:password|passwd|pwd|secret|api_key|apikey|api_secret|access_token|auth_token|private_key)\s*[=:]\s*['"]\w{8,}['"]""",
        "A credential is embedded in source. Anyone with repository access gains "
        "the secret and it cannot be rotated without a code change.",
        RiskLevel.HIGH,
        Confidence.MEDIUM,
        "Secrets",
        "CWE-798",
        [
            ".py", ".java", ".php", ".js", ".ts", ".rb", ".go", ".cs",
            ".yml", ".yaml", ".json",
        ],
        'password = "MySecretPass123"',
        'password = os.environ["DB_PASSWORD"]',
        false_positive_patterns=[
            r"example", r"placeholder", r"your_", r"<.*>", r"xxx", r"\$\{",
        ],
    ),
    _rule(
        "sast.hardcoded-crypto-key",
        "Hardcoded Cryptographic Key",
        r"""(?:key|iv|nonce|salt)\s*[=:]\s*(?:b?['"]\w{16,}['"]|bytes\s*\(\s*['"]\w{16,}['"])""",
        "An encryption key or IV is hardcoded, so the ciphertext is only as "
        "secret as the source code.",
        RiskLevel.CRITICAL,
        Confidence.HIGH,
        "Secrets",
        "CWE-321",
        [".py", ".java", ".js", ".ts", ".go", ".cs", ".php"],
        "key = b'ThisIsASecretKey1234567890123456'",
        'key = os.environ["ENCRYPTION_KEY"].encode()',
    ),
    # -------------------------------------------------------------------- Crypto
    _rule(
        "sast.weak-password-hashing",
        "Weak Password Hashing",
        r"""(?:md5|sha1)\s*\(|hashlib\.(?:md5|sha1)\(|MessageDigest\.getInstance\s*\(\s*['"](MD5|SHA-?1)['"]|password.*=.*(?:md5|sha1)""",
        "MD5 / SHA-1 are fast and broken for password storage; hashes can be "
        "brute-forced offline.",
        RiskLevel.HIGH,
        Confidence.HIGH,
        "Crypto",
        "CWE-328",
        [".py", ".java", ".php", ".js", ".ts", ".rb", ".go", ".cs"],
        "hashed = hashlib.md5(password.encode()).hexdigest()",
        "import bcrypt\nhashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())",
    ),
    _rule(
        "sast.weak-crypto-algorithm",
        "Weak Cryptographic Algorithm",
        r"""(?:DES|RC4|RC2|Blowfish|IDEA)(?:\.|\s|Cipher)|Cipher\.getInstance\s*\(\s*['"](DES|RC4|Blowfish)['"]\)|from\s+Crypto\.Cipher\s+import\s+(DES|Blowfish)|cryptography.*(?:DES|RC4|Blowfish)""",
        "DES, RC4, RC2 and Blowfish are considered insecure for confidentiality.",
        RiskLevel.HIGH,
        Confidence.MEDIUM,
        "Crypto",
        "CWE-327",
        [".py", ".java", ".js", ".ts", ".go", ".cs", ".php"],
        "from Crypto.Cipher import DES\ncipher = DES.new(key, DES.MODE_CBC)",
        "from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes\n"
        "cipher = Cipher(algorithms.AES(key), modes.GCM(iv))",
    ),
    _rule(
        "sast.insecure-random",
        "Insecure Random Number Generator",
        r"""(?:random\.random|random\.randint|Math\.random|rand\(\)|srand\(\)|mt_rand)\s*\(""",
        "A non-cryptographic RNG is used where unpredictability matters (tokens, "
        "nonces, password reset codes).",
        RiskLevel.MEDIUM,
        Confidence.LOW,
        "Crypto",
        "CWE-338",
        [".py", ".js", ".ts", ".java", ".php", ".c", ".cpp"],
        "token = ''.join(random.choices(string.ascii_letters, k=32))",
        "import secrets\ntoken = secrets.token_urlsafe(32)",
        false_positive_patterns=[r"random\.seed", r"shuffle", r"sample"],
    ),
    # ---------------------------------------------------------------------- Auth
    _rule(
        "sast.jwt-no-verify",
        "JWT Without Verification",
        r"""jwt\.decode\s*\([^)]*verify\s*=\s*False|algorithms\s*=\s*\[?\s*['"](none|HS256)['"]|\.decode\(\s*token\s*\)|jsonwebtoken\.decode\s*\(""",
        "A JWT is decoded without verifying its signature or with a weak / "
        "``none`` algorithm, so tokens can be forged.",
        RiskLevel.HIGH,
        Confidence.MEDIUM,
        "Auth",
        "CWE-347",
        [".py", ".js", ".ts", ".java", ".go"],
        "payload = jwt.decode(token, verify=False)",
        'payload = jwt.decode(token, SECRET, algorithms=["RS256"])',
    ),
    _rule(
        "sast.session-fixation",
        "Session Fixation Risk",
        r"""session\s*\[\s*['"].*['"]\s*\]\s*=.*request\.|req\.session\s*=.*req\.(body|query|params)|session_id\s*=.*(?:GET|POST|request)""",
        "A session identifier is set from request data and not regenerated after "
        "authentication.",
        RiskLevel.MEDIUM,
        Confidence.LOW,
        "Auth",
        "CWE-384",
        [".py", ".js", ".ts", ".php", ".java"],
        "session['user_id'] = user.id  # no regeneration",
        "session.regenerate()\nsession['user_id'] = user.id",
    ),
    # ------------------------------------------------------------- Deserialization
    _rule(
        "sast.insecure-deserialization-python",
        "Insecure Deserialization (Python)",
        r"""pickle\.loads?\s*\(|yaml\.(?:unsafe_)?load\s*\([^)]*(?!Loader\s*=\s*yaml\.SafeLoader)|marshal\.loads?\s*\(|shelve\.open\s*\(""",
        "Deserializing untrusted data with pickle / marshal / unsafe YAML allows "
        "remote code execution.",
        RiskLevel.CRITICAL,
        Confidence.HIGH,
        "Deserialization",
        "CWE-502",
        [".py"],
        "data = pickle.loads(user_input)",
        "import json\ndata = json.loads(user_input)  # or yaml.safe_load(...)",
        windowed=True,
    ),
    _rule(
        "sast.insecure-deserialization-java",
        "Insecure Deserialization (Java)",
        r"""ObjectInputStream\s*\(|readObject\s*\(\)|XMLDecoder\s*\(|XStream\.fromXML\s*\(|JSON\.parse\s*\(.*\)\.class""",
        "Java native deserialization of untrusted bytes can lead to remote code "
        "execution via gadget chains.",
        RiskLevel.CRITICAL,
        Confidence.MEDIUM,
        "Deserialization",
        "CWE-502",
        [".java"],
        "Object obj = new ObjectInputStream(input).readObject();",
        "ois.setObjectInputFilter(ObjectInputFilter.Config.createFilter("
        '"com.myapp.*;!*"));',
        windowed=True,
    ),
    _rule(
        "sast.insecure-deserialization-js",
        "Insecure Deserialization (JavaScript)",
        r"""(?:eval|Function)\s*\(\s*(?:JSON\.parse|atob|decodeURIComponent)|node-serialize|serialize-javascript.*(?:eval|Function)|unserialize\s*\(""",
        "Evaluating deserialized data (node-serialize / eval) executes attacker "
        "code.",
        RiskLevel.CRITICAL,
        Confidence.MEDIUM,
        "Deserialization",
        "CWE-502",
        [".js", ".ts"],
        "eval(JSON.parse(userInput).code);",
        "const data = JSON.parse(userInput);  // validate, never eval",
        windowed=True,
    ),
    # -------------------------------------------------------------------- Config
    _rule(
        "sast.debug-mode",
        "Debug Mode Enabled",
        r"""(?:DEBUG|debug)\s*[=:]\s*(?:True|true|1|['"](true|on|yes)['"])|app\.run\s*\([^)]*debug\s*=\s*True|FLASK_DEBUG\s*=\s*1""",
        "Debug mode exposes stack traces, config and an interactive console in "
        "production.",
        RiskLevel.MEDIUM,
        Confidence.HIGH,
        "Config",
        "CWE-215",
        [".py", ".js", ".ts", ".java", ".php", ".rb", ".yml", ".yaml", ".json"],
        "app.run(debug=True)",
        'DEBUG = os.environ.get("DEBUG", "false").lower() == "true"',
        false_positive_patterns=[r"#.*DEBUG", r"//.*DEBUG", r"debug.*log"],
    ),
    _rule(
        "sast.cors-wildcard",
        "CORS Wildcard",
        r"""(?:Access-Control-Allow-Origin|cors)\s*[=:]\s*['"]\*['"]|\.allowedOrigins\s*\(\s*['"]\*['"]|cors\s*\(\s*\{[^}]*origin\s*:\s*(?:true|['"]\*['"])""",
        "CORS allows every origin; combined with credentials this exposes "
        "authenticated endpoints to any site.",
        RiskLevel.MEDIUM,
        Confidence.MEDIUM,
        "Config",
        "CWE-942",
        [".py", ".java", ".js", ".ts", ".php", ".rb", ".go"],
        "cors({ origin: '*' })",
        "cors({ origin: ['https://trusted.example.com'], credentials: true })",
    ),
    _rule(
        "sast.tls-verification-disabled",
        "SSL/TLS Verification Disabled",
        r"""verify\s*[=:]\s*False|VERIFY_SSL\s*=\s*False|ssl\s*[=:]\s*False|rejectUnauthorized\s*[=:]\s*false|InsecureSkipVerify\s*[=:]\s*true|CURLOPT_SSL_VERIFYPEER.*false""",
        "Certificate validation is turned off, exposing traffic to "
        "man-in-the-middle attacks.",
        RiskLevel.HIGH,
        Confidence.HIGH,
        "Config",
        "CWE-295",
        [".py", ".java", ".js", ".ts", ".go", ".php", ".rb"],
        "requests.get(url, verify=False)",
        "requests.get(url, verify=True)",
    ),
    _rule(
        "sast.insecure-http",
        "Insecure HTTP URL",
        r"""['"](http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0)[^'"]+)['"]""",
        "A cleartext HTTP endpoint is used; transmitted data can be read or "
        "modified in transit.",
        RiskLevel.LOW,
        Confidence.LOW,
        "Config",
        "CWE-319",
        [
            ".py", ".java", ".js", ".ts", ".go", ".php", ".rb",
            ".yml", ".yaml", ".json",
        ],
        'api_url = "http://api.example.org/data"',
        'api_url = "https://api.example.org/data"',
        false_positive_patterns=[
            r"#.*http://", r"//.*http://", r"example\.com", r"schema.*http://",
        ],
    ),
    _rule(
        "sast.missing-security-headers",
        "Missing / Disabled Security Headers",
        r"""(?:Content-Security-Policy|X-Frame-Options|X-Content-Type-Options|Strict-Transport-Security)\s*[=:]\s*['"]['"]|no_header|disable.*header""",
        "Security response headers are emptied or disabled.",
        RiskLevel.LOW,
        Confidence.LOW,
        "Config",
        "CWE-693",
        [".py", ".java", ".js", ".ts", ".php", ".rb"],
        'response["X-Frame-Options"] = ""',
        'response["X-Frame-Options"] = "DENY"',
    ),
    _rule(
        "sast.open-redirect",
        "Open Redirect",
        r"""(?:redirect|res\.redirect|header\s*\(\s*['"]Location|window\.location|document\.location)\s*[=(]\s*(?:req\.|request\.|params\.|query\.|input|GET|POST|\$_)""",
        "A redirect target is taken from user input, enabling phishing via a "
        "trusted domain.",
        RiskLevel.MEDIUM,
        Confidence.MEDIUM,
        "Config",
        "CWE-601",
        [".py", ".java", ".js", ".ts", ".php", ".rb"],
        "return redirect(request.args.get('next'))",
        "target = request.args.get('next', '/')\n"
        "if urlparse(target).netloc:\n    target = '/'\n"
        "return redirect(target)",
    ),
    _rule(
        "sast.mass-assignment",
        "Mass Assignment",
        r"""(?:\.update_attributes|\.update\(|\.create\(|\.build\(|Model\.create|\.save\()\s*\(?[^)]*(?:req\.|request\.|params\[|body\[|:permit\s*\(\s*!)""",
        "User-supplied fields are bound directly onto a model, letting an "
        "attacker set attributes they should not control.",
        RiskLevel.MEDIUM,
        Confidence.LOW,
        "Config",
        "CWE-915",
        [".py", ".rb", ".java", ".js", ".ts", ".php"],
        "User.objects.create(**request.POST)",
        "User.objects.create(name=request.POST['name'], email=request.POST['email'])",
    ),
    # ----------------------------------------------------------- Info disclosure
    _rule(
        "sast.sensitive-data-in-logs",
        "Sensitive Data in Logs",
        r"""(?:log(?:ger)?\.(?:info|debug|warn|error|critical)|print|console\.log|System\.out\.print)\s*\([^)]*(?:password|secret|token|key|credit.?card|ssn|api.?key)""",
        "Credentials or personal data are written to logs, where they persist "
        "and spread to log aggregators.",
        RiskLevel.MEDIUM,
        Confidence.LOW,
        "Info Disclosure",
        "CWE-532",
        [".py", ".java", ".js", ".ts", ".rb", ".go", ".php"],
        'logger.info(f"login {username} password {password}")',
        'logger.info(f"login {username}")',
    ),
    _rule(
        "sast.stack-trace-exposure",
        "Stack Trace Exposure / Swallowed Exception",
        r"""(?:printStackTrace|traceback\.print_exc|console\.trace|e\.stack|err\.stack)\s*\(?\)?|except.*?:\s*pass|rescue\s*=>\s*nil""",
        "Internal error detail is exposed to users, or an exception is silently "
        "discarded.",
        RiskLevel.LOW,
        Confidence.LOW,
        "Info Disclosure",
        "CWE-209",
        [".py", ".java", ".js", ".ts", ".rb", ".php"],
        "except Exception as e:\n    return str(e)",
        'except Exception:\n    logger.exception("failed")\n    return {"error": "internal error"}',
    ),
    # ----------------------------------------------------------------------- SSRF
    _rule(
        "sast.ssrf",
        "Server-Side Request Forgery (SSRF)",
        r"""(?:requests\.get|urllib\.request\.urlopen|http\.get|fetch|axios\.get|HttpClient)\s*\([^)]*(?:request\.|req\.|params\.|query\.|body\.|input|GET|POST)""",
        "User input controls the target of a server-side HTTP request, reaching "
        "internal services and cloud metadata.",
        RiskLevel.HIGH,
        Confidence.MEDIUM,
        "SSRF",
        "CWE-918",
        [".py", ".java", ".js", ".ts", ".go", ".php", ".rb"],
        "response = requests.get(request.args['url'])",
        "if urlparse(url).hostname not in ALLOWED_HOSTS:\n"
        '    raise ValueError("host not allowed")\n'
        "response = requests.get(url)",
    ),
    # ------------------------------------------------------------------------ DoS
    _rule(
        "sast.redos",
        "Unsafe Regular Expression (ReDoS)",
        r"""(?:re\.compile|new\s+RegExp|regex|pattern)\s*\([^)]*(?:\+\*|\*\+|\.+\*|\.+\+|\(\.\*\)|\(\.\+\)|(?:\[[^\]]*\]){2,}\*|\{\d+,\}\*|\{\d+,\}\+)""",
        "A regex with nested / ambiguous quantifiers can hang the process on "
        "crafted input (catastrophic backtracking).",
        RiskLevel.MEDIUM,
        Confidence.LOW,
        "DoS",
        "CWE-1333",
        [".py", ".java", ".js", ".ts", ".go", ".php", ".rb"],
        "re.compile(r'(a+)+b')",
        "re.compile(r'a+b')  # no nested quantifiers",
    ),
]

RULES_BY_EXT: dict[str, list[Rule]] = {}
for _r in RULES:
    for _ext in _r.languages:
        RULES_BY_EXT.setdefault(_ext, []).append(_r)

__all__ = ["MATCH_WINDOW", "RULES", "RULES_BY_EXT", "Rule"]
