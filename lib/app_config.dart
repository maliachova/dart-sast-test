class AppConfig {
  static const String apiKey = String.fromEnvironment('API_KEY', defaultValue: '');
  static const String dbPassword = String.fromEnvironment('DB_PASSWORD', defaultValue: '');
  static const String awsSecretKey = String.fromEnvironment('AWS_SECRET_KEY', defaultValue: '');
  static const String encryptionKey = String.fromEnvironment('ENCRYPTION_KEY', defaultValue: '');

  static bool get hasRequiredConfig {
    return apiKey.isNotEmpty &&
        dbPassword.isNotEmpty &&
        awsSecretKey.isNotEmpty &&
        encryptionKey.isNotEmpty;
  }
}
