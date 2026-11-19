import 'package:flutter/material.dart';

import 'package:archaeologist_demo/services/api_client.dart';

class LoginPage extends StatefulWidget {
  const LoginPage({super.key, required this.api});
  final ApiClient api;

  @override
  State<LoginPage> createState() => _LoginPageState();
}

class _LoginPageState extends State<LoginPage> {
  final _email = TextEditingController();
  final _password = TextEditingController();
  String _status = 'Enter your password · Введите пароль';

  Future<void> _submit() async {
    final ok = await widget.api.login(_email.text, _password.text);
    setState(() => _status = ok ? 'Login successful' : 'Wrong password · Неверный пароль');
  }

  @override
  Widget build(BuildContext context) => Scaffold(
        appBar: AppBar(title: const Text('Archaeologist Demo Login')),
        body: Column(children: [
          TextField(controller: _email),
          TextField(controller: _password, obscureText: true),
          ElevatedButton(onPressed: _submit, child: const Text('Login')),
          Text(_status),
        ]),
      );
}
