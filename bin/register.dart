import 'dart:convert';
import 'dart:io';

import 'package:dart_jsonwebtoken/dart_jsonwebtoken.dart';
import 'package:mongo_dart/mongo_dart.dart';
import 'package:shelf/shelf.dart';

import 'server.dart';


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

    final String userName = data["name"];
    final String password = data['password'];

    // required minimum length name
    if (userName.length < 8 || password.length < 8) {
      return Response(HttpStatus.badRequest,
          body: "name or passowrt too short");
    }

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

    final JWT jwt = JWT(
      {
        'user': password,
        'exp': DateTime.now()
            .add(Duration(days: 24))
            .millisecondsSinceEpoch, // 24 day expiry
      },
    );
    final secretKey = generateRandomString(10);
    print(secretKey);
    final token = jwt.sign(
      SecretKey(secretKey),
    );
    final results = await jwtActiv.insertOne(
      {
        userName: {"token": token},
      },
    );

    if (results.isSuccess) {
      return Response(
        200,
        body: json.encode(token),
      );
    } else {
      await db.close();
      return Response(400, body: json.encode({"message": "faild to sign in "}));
    }
  } catch (e) {
    print(e);
    return Response(500, body: "internla server error ");
  } finally {
    await db.close();
  }
}
