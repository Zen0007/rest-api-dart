import 'dart:convert';

import 'package:dart_jsonwebtoken/dart_jsonwebtoken.dart';
import 'package:mongo_dart/mongo_dart.dart';
import 'package:shelf/shelf.dart';

import 'server.dart';


Future<Response> login(Request req) async {
  await db.open();
  
  try {
    final request = await req.readAsString();
    final data = json.decode(request);

    if (!data.containsKey('name') || !data.containsKey('password')) {
      return Response(400, body: 'Missing credentials');
    }

    final String userEmail = data['email'];
    final String user = data['name'];
    final String password = data['password'];

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
        user: {"token": token},
      },
    );

    // final email =
    //     await colection.findOne(where.eq("$user.profile.email", userEmail));
    // print(token);
    if (results.isSuccess) {
      return Response(
        200,
        body: json.encode(token),
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
