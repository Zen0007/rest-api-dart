import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'package:crypto/crypto.dart';
import 'package:shelf/shelf.dart';
import 'package:shelf/shelf_io.dart' as shelf_io;
import 'package:shelf_router/shelf_router.dart';
import 'package:mongo_dart/mongo_dart.dart';

import 'register.dart';
import 'login.dart';
import 'logout.dart';
import 'add_contact.dart';
import 'send_message.dart';
import 'get_message.dart';

final url =
    Platform.environment['MONGO_URL'] ?? 'mongodb://localhost:27017/chat';
final db = Db(url);
final colection = db.collection('main');

final blacklistedTokens = db.collection('blaclistoken');
final jwtActiv = db.collection("activeJwtToken");

String hashPassword(String password) {
  final bytes = utf8.encode(password);
  final digest = sha256.convert(bytes);
  return digest.toString();
}

String generateRandomString(int length) {
  const chars =
      'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#\$%^&*()_+';
  Random rnd = Random();
  return List.generate(length, (index) => chars[rnd.nextInt(chars.length)])
      .join();
}

void main(List<String> args) async {
  final ip = InternetAddress.anyIPv4;

// Configure routes.
  final router = Router()
    ..post("/register", register)
    ..post("/login", login)
    ..post("/logout", logout)
    ..post("/addcontact", addContact)
    ..post("/sendmessage", sendMassage)
    ..get("/getmessages", getMassage);

  // Configure a pipeline that logs requests.
  print(url);
  try {
    final handler =
        Pipeline().addMiddleware(logRequests()).addHandler(router.call);

    // For running in containers, we respect the PORT environment variable.
    final port = int.parse(Platform.environment['PORT'] ?? '8080');
    final server = await shelf_io.serve(handler, ip, port);
    print('Server listening on port ${server.address}');
  } catch (e, s) {
    print(e);
    print(s);
  }
}
