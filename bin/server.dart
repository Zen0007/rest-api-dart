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

final db = Db('mongodb://localhost:27017/chat');
final colection = db.collection('main');

final blacklistedTokens = db.collection('blaclistoken');
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
  await db.open();
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

    final chekUser = await colection.findOne(where.eq('userName', userName));
    if (chekUser != null) {
      return Response(400, body: 'User already exists');
    }

    print(data['name']);
    print(data['email']);
    print(data['password']);

    // database['user'][userName] = {
    //   'profile': {
    //     'name': data['name'],
    //     'email': data['email'],
    //     'password': password,
    //   },
    //   'contact': {}
    // };
    await colection.insertMany(
      [
        {
          userName: {
            "profile": {
              'name': userName,
              'email': data['email'],
              'password': password,
            },
          }
        },
      ],
    );
    print(database);
    return Response(201, body: "success to resgister");
  } catch (e) {
    print(e);
    return Response(500, body: "internla server error ");
  } finally {
    await db.close();
  }
}

Future<Response> login(Request req) async {
  await db.open();
  try {
    final request = await req.readAsString();
    final data = json.decode(request);

    if (!data.containsKey('name') || !data.containsKey('password')) {
      return Response(400, body: 'Missing credentials');
    }

    final userEmail = data['email'];
    final user = data['name'];
    final password = data['password'];

    final document = await colection.findOne(
      where.exists('main.$user.profile.password'),
    );

    //chek if data user is null
    if (document == null) {
      return Response(401, body: "missing input user name");
    }
    final hashedPassword = hashPassword(password);

    //chek if passeword user is null
    if (document['main'][user]['profile']['password'] != hashedPassword) {
      return Response(401, body: "invalid password");
    }

    //chek if email is null
    if (document['main'][user]['profile']['email'] != userEmail) {
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

    return Response(
      201,
      body: json.encode(
        {
          "token": token,
          "user": {
            "name": user,
            "email": document['main'][user]['profile']['email'],
          },
        },
      ),
      headers: {'content-type': 'application/json'},
    );
  } catch (e) {
    return Response(500, body: "internal server error");
  } finally {
    await db.close();
  }
}

Future<Response> logout(Request req) async {
  await db.open();
  try {
    final token = req.headers['Authorization']?.split('Bearer ').last;

    if (token != null) {
      blacklistedTokens.insert(
        {
          "token": token,
        },
      );
      return Response.ok(json.encode({'message': 'Logout successful'}),
          headers: {'content-type': 'application/json'});
    }
    return Response(400, body: "invalid logout resquest");
  } catch (e) {
    print(e);
    return Response(500, body: "invlaid server error $e");
  } finally {
    await db.close();
  }
}

Future<Response> addContact(Request req) async {
  await db.open();
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

    final document = await colection.findOne(
      where.exists('main.$user.contact.$contact'),
    );

    if (document != null) {
      return Response(400, body: 'Contact already exists ');
    }

    if (document == null) {
      return Response(400, body: 'not had exist user or contact ');
    }

    // database['user'][user]['contact'][contact] = {
    //   "chat": [],
    // };

    final chat = {
      "chat": [],
    };

    final results = await colection.updateOne(
      where.eq('main', user),
      modify.set(
        'contact.$contact',
        chat,
      ),
    );

    if (results.isSuccess) {
      return Response(201, body: "success");
    } else {
      return Response(400, body: "invalid add contact");
    }
  } catch (e, s) {
    print("$e  ===============");
    print(s);
    return Response(500, body: "internal server error ");
  } finally {
    await db.close();
  }
}

Future<Response> sendMassage(Request req) async {
  await db.open();
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

    final isEmpty = await colection.count();
    // Check if the database is null or empty
    if (isEmpty == 0) {
      return Response(500, body: 'Database is null or empty');
    }

    final isSender = await colection.findOne(
      where.exists('main.$sender'),
    );
    // Check if the sender exists in the database
    if (isSender == null) {
      return Response(400, body: 'Invalid sender');
    }

    final isReceiver = await colection.findOne(
      where.exists('main.$receiver'),
    );
    // Check if the receiver exists in the database
    if (isReceiver == null) {
      return Response(400, body: 'Invalid receiver');
    }

    // Create the message object
    final messageObject = {
      "text": message,
      "time": time,
    };

    final updateSender = await colection.updateOne(where.eq("main", sender),
        modify.push("main.$sender.contact.$receiver.chat", messageObject));

    final updateReceiver = await colection.updateOne(
      where.eq("main", receiver),
      modify.push("main.$receiver.contact.$sender.chat", messageObject),
    );

    if (updateSender.isSuccess && updateReceiver.isSuccess) {
      return Response(201, body: "Success send message");
    } else {
      return Response(400, body: "invalid send message");
    }
    // // Add the message to both sender's and receiver's chat
    // database['user'][sender]['contact'][receiver]["chat"].add(messageObject);
    // database['user'][receiver]['contact'][sender]["chat"].add(messageObject);
    // print(database);
  } catch (e, s) {
    print("Error: $e"); // Log the error for debugging
    print("Stack trace: $s");
    return Response(500,
        body:
            "Internal server error: $e   ==${data['receiver']}  ${data['sender']}");
  } finally {
    await db.close();
  }
}

Future<Response> getMassage(Request req) async {
  await db.open();
  try {
    final user = req.url.queryParameters["main"];
    final contact = req.url.queryParameters['contact'];

    if (user == null || contact == null) {
      return Response(400, body: "invalid user or contact");
    }

    final chekDataUser = await colection.findOne(where.eq("main", user));

    if (chekDataUser == null) {
      return Response(400, body: 'Invalid user or contact');
    }

    if (!chekDataUser['contact'].containsKey(contact)) {
      return Response(400, body: "not exist contact");
    }

    final massage = chekDataUser['main'][user]['contact'][contact]['chat'];

    return Response(
      200,
      body: json.encode(massage),
      headers: {'content-type': 'application/json'},
    );
  } catch (e) {
    return Response(500, body: "internal server error");
  } finally {
    await db.close();
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
