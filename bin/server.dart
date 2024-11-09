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
final jwtActiv = db.collection("activeJwtToken");

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
    final password = data['password'];

    final chekUser = await colection.findOne(where.exists(userName));
    if (chekUser != null) {
      await db.close();
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
      where.exists(user),
    );

    //chek if data user is null
    if (document == null) {
      await db.close();
      return Response(401, body: "not exist user");
    }

    final findEmail =
        await colection.findOne(where.eq("$user.profile.email", userEmail));
    //chek if email is null
    if (findEmail == null) {
      await db.close();
      return Response(401, body: "invalid email");
    }

    final findPassword =
        await colection.findOne(where.eq("$user.profile.password", password));
    //chek if passeword user is null
    if (findPassword == null) {
      await db.close();
      return Response(401, body: "invalid password");
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

    final results = await jwtActiv.insertOne(
      {
        user: {"token": token},
      },
    );

    final email =
        await colection.findOne(where.eq("$user.profile.email", userEmail));
    print(token);
    if (results.isSuccess) {
      return Response(
        201,
        body: json.encode(
          {
            "token": token,
            "user": {
              "name": user,
              "email": email![user]['profile']['email'],
            },
          },
        ),
        headers: {'content-type': 'application/json'},
      );
    } else {
      await db.close();
      return Response(400, body: "faild to login");
    }
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

    final document =
        await colection.findOne(where.eq('$user.contact.$contact', contact));

    if (document != null) {
      return Response(400, body: 'Contact already exists ');
    }

    final findContact = await colection.findOne(where.exists(contact));
    if (findContact == null) {
      return Response(400, body: "contact not exist in database");
    }

    // database['user'][user]['contact'][contact] = {
    //   "chat": [],
    // };
    final id = await colection.findOne(where.eq("$user.profile.name", user));
    final idUser = id!["_id"];

    await colection.update(
      where.eq('_id', idUser),
      {
        '\$set': {
          "$user.contact": {
            contact: {
              "chat": [],
            }
          },
        }
      },
    );

    return Response(200, body: "success to add contact");
  } catch (e, s) {
    print("$e  ===============");
    print("$s   ------------------");
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
    final time = DateTime.now();
    final date =
        '${"${time.year}".padLeft(4, '0')}-${"${time.month}".padLeft(2, '0')}-${"${time.day}".padLeft(2, '0')} ${"${time.hour}".padLeft(2, '0')}:${"${time.minute}".padLeft(2, '0')}';

    print('Sender: $sender');
    print('Receiver: $receiver');

    // Log the entire database structure for debugging
    print('Database: $database');

    final isSender = await colection.findOne(
      where.exists('$sender'),
    );
    // Check if the sender exists in the database
    if (isSender == null) {
      return Response(400, body: 'Invalid sender');
    }

    final isReceiver = await colection.findOne(
      where.exists('$receiver'),
    );
    // Check if the receiver exists in the database
    if (isReceiver == null) {
      return Response(400, body: 'Invalid receiver');
    }

    final id =
        await colection.findOne(where.eq("$sender.profile.name", sender));
    final idSender = id!["_id"];

    // update sender
    final updateSender = await colection.updateOne(
      where.eq('_id', idSender),
      modify.push(
        "$sender.contact.$receiver.chat",
        {
          "text": message,
          "time": date,
        },
      ),
    );

    final idtwo =
        await colection.findOne(where.eq("$receiver.profile.name", receiver));
    final idReceiver = idtwo!["_id"];

    // update receiver
    final updateReceiver = await colection.updateOne(
      where.eq("_id", idReceiver),
      modify.push(
        "$receiver.contact.$sender.chat",
        {
          "text": message,
          "time": date,
        },
      ),
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
    final user = req.url.queryParameters['main'];
    final contact = req.url.queryParameters['contact'];

    if (user == null || contact == null) {
      return Response.badRequest(
          body: json.encode({
            'error': 'Invalid parameters',
            'message': 'Both user and contact are required'
          }),
          headers: {'content-type': 'application/json'});
    }
    final id = await colection.findOne(where.exists(user));

    if (id == null) {
      return Response(400, body: "not exist contact $id $user $contact");
    }

    if (id[user]['contact'][contact] == null) {
      return Response(404, body: "not have contact exits");
    }

    final massage = id[user]['contact'][contact];

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
