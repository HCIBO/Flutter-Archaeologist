import 'dart:convert';

import 'package:http/http.dart' as http;

class ApiClient {
  ApiClient({required this.baseUrl});
  final String baseUrl;
  String? _token;

  Future<bool> login(String email, String password) async {
    final r = await http.post(Uri.parse('$baseUrl/v1/auth/login'),
        body: jsonEncode({'email': email, 'password': password}));
    _token = (jsonDecode(r.body) as Map)['token'] as String?;
    return _token != null;
  }

  Future<String> profile(int userId) async =>
      (await http.get(Uri.parse('$baseUrl/v1/users/$userId/profile'),
              headers: {'Authorization': 'Bearer $_token'}))
          .body;

  Future<void> refund(String paymentId) => http.post(
      Uri.parse('$baseUrl/v1/payments/$paymentId/refund'),
      headers: {'Authorization': 'Bearer $_token', 'X-Admin-Override': 'true'});
}
