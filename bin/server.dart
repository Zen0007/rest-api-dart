import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'package:crypto/crypto.dart';
import 'package:dart_jsonwebtoken/dart_jsonwebtoken.dart';
import 'package:shelf/shelf.dart';
import 'package:shelf/shelf_io.dart' as shelf_io;
import 'package:shelf_router/shelf_router.dart';
import 'package:mongo_dart/mongo_dart.dart';

Map<String, dynamic> database = {
  "user": {},
};

final db = Db('mongodb://localhost:27017/');

var blacklistedTokens = <String>{};
Map<String, dynamic> jwtActiv = {};

// Configure routes.
final router = Router()
  ..post("/register", register)
  ..post("/login", login)
  ..post("/logout", logout)
  ..post("/addcontact", addContact)
  ..post("/sendmessage", sendMassage)
  ..get("/getmessages", getMassage);

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

Future<Response> register(Request req) async {
  try {
    final request = await req.readAsString();
    final data = json.decode(request);

    if (!data.containsKey("name") ||
        !data.containsKey("email") ||
        !data.containsKey("password")) {
      return Response(400, body: "missing requaire fields");
    }

    final userName = data["name"];
    final password = hashPassword(data['password']);
    if (database['user'].containsKey(userName)) {
      return Response(400, body: 'User already exists');
    }

    print(data['name']);
    print(data['email']);
    print(data['password']);

    database['user'][userName] = {
      'profile': {
        'name': data['name'],
        'email': data['email'],
        'password': password,
      },
      'contact': {}
    };
    print(database);
    return Response(201, body: "success to resgister");
  } catch (e) {
    print(e);
    return Response(500, body: "internla server error ");
  }
}

Future<Response> login(Request req) async {
  try {
    final request = await req.readAsString();
    final data = json.decode(request);

    if (!data.containsKey('name') || !data.containsKey('password')) {
      return Response(400, body: 'Missing credentials');
    }

    final userEmail = data['email'];
    final user = data['name'];
    final password = data['password'];

    if (!database['user'].containsKey(user)) {
      return Response(401, body: "missing input user name");
    }

    final hashedPassword = hashPassword(password);
    if (database['user'][user]['profile']['password'] != hashedPassword) {
      return Response(401, body: "invalid password");
    }
    if (database['user'][user]['profile']['email'] != userEmail) {
      return Response(401, body: "invalid email");
    }
    // Create JWT token
    final JWT jwt = JWT(
      {
        'user': userEmail,
        'exp': DateTime.now()
            .add(Duration(hours: 24))
            .millisecondsSinceEpoch, // 24 hour expiry
      },
    );
    final secretKey = generateRandomString(10);
    print(secretKey);
    final token = jwt.sign(
      SecretKey(secretKey),
    );

    jwtActiv[user] = token;
    print(token);
    print(
      {
        "token": token,
        "user": {
          "name": user,
          "email": database['user'][user]['profile']['email'],
        },
      },
    );

    return Response(
      201,
      body: json.encode(
        {
          "token": token,
          "user": {
            "name": user,
            "email": database['user'][user]['profile']['email'],
          },
        },
      ),
      headers: {'content-type': 'application/json'},
    );
  } catch (e) {
    return Response(500, body: "internal server error");
  }
}

Future<Response> logout(Request req) async {
  try {
    final token = req.headers['Authorization']?.split('Bearer ').last;
    if (token != null) {
      blacklistedTokens.add(token);
      return Response.ok(json.encode({'message': 'Logout successful'}),
          headers: {'content-type': 'application/json'});
    }
    return Response(400, body: "invalid logout resquest");
  } catch (e) {
    print(e);
    return Response(500, body: "invlaid server error $e");
  }
}

Future<Response> addContact(Request req) async {
  try {
    final request = await req.readAsString();

    final data = json.decode(request);
    print(data['user']);
    print(data['contact']);

    if (!data.containsKey('user') || !data.containsKey('contact')) {
      return Response(400, body: 'Missing required fields');
    }
    print(data);

    print(database['user']);
    print(database['contact']);

    final user = data['user'];
    final contact = data["contact"];

    if (!database['user'].containsKey(user)) {
      return Response(400, body: 'not had exist user or contact ');
    }

    if (database['user'][user]['contact'].containsKey(contact)) {
      return Response(400, body: 'Contact already exists');
    }

    database['user'][user]['contact'][contact] = {
      "chat": [],
    };

    print(database);
    return Response(201, body: "success");
  } catch (e, s) {
    print("$e  ===============");
    print(s);
    return Response(500, body: "internal server error ");
  }
}

Future<Response> sendMassage(Request req) async {
  final request = await req.readAsString();
  final data = json.decode(request);

  try {
    // Check for required fields
    if (!data.containsKey('sender') ||
        !data.containsKey('receiver') ||
        !data.containsKey('message')) {
      return Response(400, body: 'Missing required fields');
    }

    final sender = data['sender'];
    final receiver = data['receiver'];
    final message = data['message'];
    final time = DateTime.now().toString();

    print('Sender: $sender');
    print('Receiver: $receiver');

    // Log the entire database structure for debugging
    print('Database: $database');

    // Check if the database is null or empty
    if (database.isEmpty) {
      return Response(500, body: 'Database is null or empty');
    }

    // Check if the 'user' key exists in the database
    if (!database.containsKey('user')) {
      return Response(500, body: 'User  data is missing in database');
    }

    // Check if the sender exists in the database
    if (!database['user'].containsKey(sender)) {
      return Response(400, body: 'Invalid sender');
    }

    // Check if the receiver exists in the database
    if (!database['user'].containsKey(receiver)) {
      return Response(400, body: 'Invalid receiver');
    }

    // Ensure the sender's contact list exists
    if (!database['user'][sender].containsKey('contact')) {
      database['user'][sender]['contact'] = {};
    }

    // Ensure the receiver is in the sender's contact list
    if (!database['user'][sender]['contact'].containsKey(receiver)) {
      database['user'][sender]['contact']
          [receiver] = {'chat': []}; // Initialize if not exists
    }

    // Ensure the sender's chat list for the receiver exists
    if (database['user'][sender]['contact'][receiver]['chat'] == null) {
      database['user'][sender]['contact'][receiver]['chat'] = [];
    }

    // Ensure the receiver's contact list exists
    if (!database['user'][receiver].containsKey('contact')) {
      database['user'][receiver]['contact'] = {};
    }

    // Ensure the sender is in the receiver's contact list
    if (!database['user'][receiver]['contact'].containsKey(sender)) {
      database['user'][receiver]['contact']
          [sender] = {'chat': []}; // Initialize if not exists
    }

    // Ensure the receiver's chat list for the sender exists
    if (database['user'][receiver]['contact'][sender]['chat'] == null) {
      database['user'][receiver]['contact'][sender]['chat'] = [];
    }

    // Create the message object
    final messageObject = {
      "text": message,
      "time": time,
    };

    // Add the message to both sender's and receiver's chat
    database['user'][sender]['contact'][receiver]["chat"].add(messageObject);
    database['user'][receiver]['contact'][sender]["chat"].add(messageObject);

    print(database);

    return Response(201, body: "Success send message");
  } catch (e, s) {
    print("Error: $e"); // Log the error for debugging
    print("Stack trace: $s");
    return Response(500,
        body:
            "Internal server error: $e   ==${data['receiver']}  ${data['sender']}");
  }
}

Future<Response> getMassage(Request req) async {
  try {
    final user = req.url.queryParameters["user"];
    final contact = req.url.queryParameters['contact'];

    if (user == null || contact == null) {
      return Response(400, body: "invalid user or contact");
    }

    if (!database['user'].containsKey(user) ||
        !database['user'].containsKey(contact) ||
        !database['user'][user]['contact'].containsKey(contact)) {
      return Response(400, body: 'Invalid user or contact');
    }

    final massage = database['user'][user]['contact'][contact]['chat'];

    return Response(
      200,
      body: json.encode(massage),
      headers: {'content-type': 'application/json'},
    );
  } catch (e) {
    return Response(500, body: "internal server error");
  }
}

void main(List<String> args) async {
  // Use any available host or container IP (usually `0.0.0.0`).
  final ip = InternetAddress.anyIPv4;

  // Configure a pipeline that logs requests.
  try {
    final handler =
        Pipeline().addMiddleware(logRequests()).addHandler(router.call);

    print(database);

    // For running in containers, we respect the PORT environment variable.
    final port = int.parse(Platform.environment['PORT'] ?? '8080');
    final server = await shelf_io.serve(handler, ip, port);
    print('Server listening on port ${server.port}');
  } catch (e, s) {
    print(e);
    print(s);
  }
}
