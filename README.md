# Bad Dart App 🚨

⚠️ **DANGER: This is an intentionally vulnerable application for SAST testing.**

## Vulnerabilities Included

### SQL Injection (CWE-89)
- Login bypass
- Search injection
- ORDER BY injection
- UPDATE/DELETE injection

### Weak Cryptography (CWE-327, CWE-330)
- MD5 hashing
- SHA1 hashing
- No salt in hashing
- Weak encryption (XOR)
- Predictable random numbers

### Command Injection (CWE-78)
- Direct command execution
- Unsanitized file operations

### Path Traversal (CWE-22)
- File read without validation
- File delete without sanitization

### Network Vulnerabilities
- SSRF (CWE-918)
- Certificate validation disabled (CWE-295)
- Cleartext transmission (CWE-319)
- Sensitive data in URLs (CWE-598)

### Authorization Issues
- IDOR (CWE-639)
- Missing authorization checks (CWE-862)

### Information Disclosure
- Hardcoded credentials (CWE-798)
- Logging sensitive data (CWE-532)
- Error message exposure (CWE-209)

### Others
- Race conditions (CWE-362)
- ReDoS (CWE-1333)
- Unrestricted file upload (CWE-434)

## Running

```bash
# Install dependencies
dart pub get

# Run the vulnerable app
dart run lib/main.dart