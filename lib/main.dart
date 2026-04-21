import 'dart:io';
import 'dart:convert';
import 'dart:math';
import 'package:crypto/crypto.dart';
import 'package:http/http.dart' as http;
import 'package:sqflite/sqflite.dart';
import 'package:path/path.dart';

void main() async {
  // CWE-489: Debug code in production
  print('🚨 Starting Bad Dart App...');
  print('API Key: $API_KEY');
  print('DB Password: $DB_PASSWORD');
  print('AWS Secret: $AWS_SECRET_KEY');
  print('Encryption Key: $ENCRYPTION_KEY');
  final app = BadDartApp();
  await app.runApp();
}

class BadDartApp {
  late Database _database;
  
  // CWE-543: Public instance variables
  String currentUserPassword = '';
  String sessionToken = '';
  Map<String, dynamic> sensitiveData = {};
  
  Future<void> runApp() async {
    print('\n=== Testing All Vulnerabilities ===\n');
    
    await initDatabase();
    await demonstrateVulnerabilities();
  }
  
  // ========== DATABASE VULNERABILITIES ==========
  
  Future<void> initDatabase() async {
    final dbPath = await getDatabasesPath();
    final path = join(dbPath, 'vulnerable.db');
    
    _database = await openDatabase(
      path,
      version: 1,
      onCreate: (db, version) async {
        await db.execute('''
          CREATE TABLE users (
            id INTEGER PRIMARY KEY,
            username TEXT,
            password TEXT,
            email TEXT,
            ssn TEXT,
            credit_card TEXT
          )
        ''');
        
        await db.execute('''
          CREATE TABLE products (
            id INTEGER PRIMARY KEY,
            name TEXT,
            price REAL
          )
        ''');
      },
    );
  }
  
  // CWE-89: SQL Injection - String concatenation
  Future<Map<String, dynamic>?> login(String username, String password) async {
    // VULNERABLE: Direct string concatenation
    final query = "SELECT * FROM users WHERE username = '$username' AND password = '$password'";
    
    print('Executing query: $query');
    final result = await _database.rawQuery(query);
    
    if (result.isNotEmpty) {
      // CWE-312: Storing password in plaintext
      currentUserPassword = password;
      sensitiveData = result.first;
      
      // CWE-532: Logging sensitive information
      print('Login successful! User data: $result');
      print('SSN: ${result.first['ssn']}');
      print('Credit Card: ${result.first['credit_card']}');
      
      return result.first;
    }
    
    // CWE-209: Information exposure through error messages
    print('Login failed for user: $username with password: $password');
    return null;
  }
  
  // CWE-89: SQL Injection in search
  Future<List<Map<String, dynamic>>> searchUsers(String searchTerm) async {
    final query = "SELECT * FROM users WHERE username LIKE '%$searchTerm%'";
    return await _database.rawQuery(query);
  }
  
  // CWE-89: SQL Injection in ORDER BY
  Future<List<Map<String, dynamic>>> getProducts(String sortBy) async {
    final query = "SELECT * FROM products ORDER BY $sortBy";
    return await _database.rawQuery(query);
  }
  
  // CWE-89: SQL Injection in UPDATE
  Future<void> updateUserEmail(String userId, String newEmail) async {
    final query = "UPDATE users SET email = '$newEmail' WHERE id = $userId";
    await _database.rawUpdate(query);
  }
  
  // CWE-89: SQL Injection in DELETE
  Future<void> deleteUser(String username) async {
    final query = "DELETE FROM users WHERE username = '$username'";
    await _database.rawDelete(query);
  }
  
  // ========== CRYPTOGRAPHY VULNERABILITIES ==========
  
  // CWE-327: Use of weak hash (MD5)
  String hashPasswordMD5(String password) {
    return md5.convert(utf8.encode(password)).toString();
  }
  
  // CWE-327: Use of weak hash (SHA1)
  String hashPasswordSHA1(String password) {
    return sha1.convert(utf8.encode(password)).toString();
  }
  
  // CWE-759: Hash without salt
  String hashPasswordNoSalt(String password) {
    return sha256.convert(utf8.encode(password)).toString();
  }
  
  // CWE-760: Weak salt
  String hashPasswordWeakSalt(String password) {
    const salt = 'abc'; // Hardcoded weak salt
    return sha256.convert(utf8.encode(password + salt)).toString();
  }
  
  // CWE-326: Weak encryption (XOR)
  String weakEncrypt(String data, String key) {
    final dataBytes = utf8.encode(data);
    final keyBytes = utf8.encode(key);
    final encrypted = <int>[];
    
    for (int i = 0; i < dataBytes.length; i++) {
      encrypted.add(dataBytes[i] ^ keyBytes[i % keyBytes.length]);
    }
    
    return base64.encode(encrypted);
  }
  
  // CWE-330: Weak random number generator
  String generateWeakToken() {
    final random = Random(DateTime.now().millisecondsSinceEpoch); // Predictable seed
    return random.nextInt(999999).toString();
  }
  
  // CWE-338: Weak PRNG for cryptographic purposes
  String generateSessionId() {
    final random = Random();
    return random.nextInt(1000000000).toString();
  }
  
  // ========== COMMAND INJECTION ==========
  
  // CWE-78: OS Command Injection
  Future<String> executeCommand(String command) async {
    try {
      // VULNERABLE: Direct execution of user input
      final result = await Process.run('sh', ['-c', command]);
      return result.stdout.toString();
    } catch (e) {
      // CWE-209: Detailed error exposure
      return 'Error: ${e.toString()}';
    }
  }
  
  // CWE-78: Command injection in file operations
  Future<void> compressFile(String filename) async {
    await Process.run('tar', ['-czf', '$filename.tar.gz', filename]);
  }
  
  // ========== FILE VULNERABILITIES ==========
  
  // CWE-22: Path Traversal
  Future<String> readFile(String filename) async {
    // VULNERABLE: No path sanitization
    final file = File('/app/data/$filename');
    return await file.readAsString();
  }
  
  // CWE-434: Unrestricted file upload
  Future<void> saveUploadedFile(String filename, List<int> content) async {
    // VULNERABLE: No file type validation
    final file = File('/uploads/$filename');
    await file.writeAsBytes(content);
  }
  
  // CWE-73: External control of file path
  Future<void> deleteFile(String filepath) async {
    final file = File(filepath);
    if (await file.exists()) {
      await file.delete();
    }
  }
  
  // ========== NETWORK VULNERABILITIES ==========
  
  // CWE-918: Server-Side Request Forgery (SSRF)
  Future<String> fetchUrl(String url) async {
    // VULNERABLE: No URL validation
    final response = await http.get(Uri.parse(url));
    return response.body;
  }
  
  // CWE-295: Improper certificate validation
  Future<String> fetchUrlInsecure(String url) async {
    final httpClient = HttpClient()
      ..badCertificateCallback = ((cert, host, port) => true); // Accept all certs!
    
    final request = await httpClient.getUrl(Uri.parse(url));
    final response = await request.close();
    return await response.transform(utf8.decoder).join();
  }
  
  // CWE-319: Cleartext transmission of sensitive data
  Future<void> sendPassword(String username, String password) async {
    // VULNERABLE: Using HTTP instead of HTTPS
    await http.post(
      Uri.parse('http://api.example.com/login'),
      body: {'username': username, 'password': password},
    );
  }
  
  // CWE-598: Sensitive data in GET parameters
  Future<void> authenticateViaUrl(String username, String password, String ssn) async {
    await http.get(
      Uri.parse('https://api.example.com/auth?user=$username&pass=$password&ssn=$ssn')
    );
  }
  
  // ========== AUTHORIZATION VULNERABILITIES ==========
  
  // CWE-639: Insecure Direct Object Reference (IDOR)
  Future<Map<String, dynamic>?> getUserProfile(String userId) async {
    // VULNERABLE: No authorization check
    final result = await _database.rawQuery(
      'SELECT * FROM users WHERE id = $userId'
    );
    return result.isNotEmpty ? result.first : null;
  }
  
  // CWE-862: Missing authorization
  Future<void> deleteUserAccount(String userId) async {
    // VULNERABLE: Anyone can delete any user
    await _database.rawDelete('DELETE FROM users WHERE id = $userId');
  }
  
  // ========== INFORMATION DISCLOSURE ==========
  
  // CWE-200: Exposure of sensitive information
  String dumpUserData(Map<String, dynamic> user) {
    return '''
    User Information:
    - Username: ${user['username']}
    - Password: ${user['password']}
    - Email: ${user['email']}
    - SSN: ${user['ssn']}
    - Credit Card: ${user['credit_card']}
    ''';
  }
  
  // CWE-532: Insertion of sensitive information into log
  void logUserActivity(String username, String action) {
    print('[$username] performed: $action');
    print('Session Token: $sessionToken');
    print('Current Password: $currentUserPassword');
    print('Sensitive Data: $sensitiveData');
  }
  
  // ========== REGEX VULNERABILITIES ==========
  
  // CWE-1333: ReDoS (Regular Expression Denial of Service)
  bool validateEmail(String email) {
    // VULNERABLE: Catastrophic backtracking
    final regex = RegExp(r'^([a-zA-Z0-9]+)*@([a-zA-Z0-9]+)*\.com$');
    return regex.hasMatch(email);
  }
  
  // ========== RACE CONDITIONS ==========
  
  // CWE-362: Race condition
  int accountBalance = 1000;
  
  Future<void> withdraw(int amount) async {
    // VULNERABLE: No locking mechanism
    if (accountBalance >= amount) {
      await Future.delayed(Duration(milliseconds: 100)); // Simulate delay
      accountBalance -= amount;
      print('Withdrew: \$$amount, Balance: \$$accountBalance');
    }
  }
  
  // ========== DEMONSTRATION ==========
  
  Future<void> demonstrateVulnerabilities() async {
    print('1. SQL Injection Demo:');
    await login("admin' OR '1'='1", "anything");
    
    print('\n2. Weak Crypto Demo:');
    print('MD5 Hash: ${hashPasswordMD5("password123")}');
    print('Weak Token: ${generateWeakToken()}');
    print('Weak Encryption: ${weakEncrypt("secret data", "key")}');
    
    print('\n3. Command Injection Demo:');
    print('Command result: ${await executeCommand("echo 'Hello'; ls -la")}');
    
    print('\n4. Path Traversal Demo:');
    try {
      await readFile('../../etc/passwd');
    } catch (e) {
      print('Path traversal attempted: $e');
    }
    
    print('\n5. SSRF Demo:');
    try {
      await fetchUrl('http://localhost:8080/admin');
    } catch (e) {
      print('SSRF attempted: $e');
    }
    
    print('\n6. Information Disclosure Demo:');
    logUserActivity('admin', 'login');
    
    print('\n7. Weak Random Demo:');
    for (int i = 0; i < 5; i++) {
      print('Weak token $i: ${generateWeakToken()}');
    }
    
    print('\n8. Race Condition Demo:');
    await Future.wait([
      withdraw(600),
      withdraw(600),
    ]);
    
    print('\n=== All vulnerabilities demonstrated ===');
  }
}

// ========== ADDITIONAL BAD PRACTICES ==========

// CWE-798: More hardcoded secrets
class ApiConfig {
  static const String githubToken = 'ghp_1234567890abcdefghijklmnopqrstuvwxyz';
  static const String slackWebhook = 'https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXX';
  static const String databaseUrl = 'postgresql://admin:password123@localhost:5432/production';
  static const String jwtSecret = 'super-secret-jwt-key-do-not-share';
}

// CWE-502: Unsafe deserialization (conceptual in Dart)
class UnsafeSerializer {
  static dynamic deserialize(String data) {
    // In languages with native serialization, this would be dangerous
    return jsonDecode(data); // Still shows the pattern
  }
}

// CWE-601: Open redirect
class Router {
  static void redirect(String url) {
    // VULNERABLE: No validation of redirect URL
    print('Redirecting to: $url');
    // In a web context, this would be: window.location.href = url
  }
}

// CWE-91: XML Injection (conceptual)
class XmlBuilder {
  static String createUser(String username, String email) {
    // VULNERABLE: No sanitization
    return '''
    <user>
      <username>$username</username>
      <email>$email</email>
    </user>
    ''';
    // User can inject: </username><admin>true</admin><username>
  }
}