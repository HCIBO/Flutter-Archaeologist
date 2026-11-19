import 'dart:async';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_dotenv/flutter_dotenv.dart';
import 'package:http/http.dart' as http;

import 'package:archaeologist_demo/services/api_client.dart';
import 'package:archaeologist_demo/pages/login_page.dart';

const supabaseUrl = String.fromEnvironment('SUPABASE_URL');
const supabaseAnonKey = String.fromEnvironment('SUPABASE_KEY');
const googleApiKey = String.fromEnvironment('GOOGLE_KEY');
const firebaseDb = String.fromEnvironment('FIREBASE_DB');

const vault = MethodChannel('com.archaeologist.demo/vault');
const security = MethodChannel('com.archaeologist.demo/security');

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  await dotenv.load(fileName: 'assets/env/app.env');
  runApp(const DemoApp());
  unawaited(backgroundSync().catchError((_) {}));
  unawaited(readVaultSecret().catchError((_) => ''));
  unawaited(pinnedClient().catchError((_) => HttpClient()));
  unawaited(security.invokeMethod('deviceStatus').then((s) => print('SECURITY $s')).catchError((_) {}));
  Timer.periodic(const Duration(seconds: 3), (_) => tlsProbe());
}

Future<void> tlsProbe() async {
  try {
    final req = await HttpClient().getUrl(Uri.parse('https://127.0.0.1:8443/probe'));
    final res = await req.close();
    final body = await res.transform(const SystemEncoding().decoder).join();
    print('TLSPROBE ok ${res.statusCode} $body');
  } catch (e) {
    print('TLSPROBE fail $e');
  }
}

class DemoApp extends StatelessWidget {
  const DemoApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Archaeologist Demo',
      home: LoginPage(api: ApiClient(baseUrl: 'https://api.archaeologist-demo.example')),
    );
  }
}

Future<HttpClient> pinnedClient() async {
  final pem = await rootBundle.load('assets/certs/api_pin.pem');
  final ctx = SecurityContext(withTrustedRoots: false)
    ..setTrustedCertificatesBytes(pem.buffer.asUint8List());
  return HttpClient(context: ctx);
}

Future<String> readVaultSecret() async =>
    await vault.invokeMethod<String>('getDeviceSecret') ?? '';

Future<void> backgroundSync() async {
  await http.post(Uri.parse('$supabaseUrl/rest/v1/events'),
      headers: {'apikey': supabaseAnonKey, 'Authorization': 'Bearer $supabaseAnonKey'});
  await http.get(Uri.parse('$firebaseDb/users.json'));
  await http.get(Uri.parse('https://maps.googleapis.com/maps/api/geocode/json?key=$googleApiKey'));
}
