import 'dart:convert';

import 'package:mongo_dart/mongo_dart.dart';
import 'package:shelf/shelf.dart';

import 'server.dart';



Future<Response> getMassage(Request req) async {
  await db.open();
  try {
    final user = req.url.queryParameters["user"];
    final contact = req.url.queryParameters["contact"];

    print(user);
    print(contact);

    if (user == null || contact == null) {
      return Response.badRequest(
          body: 'Both user and contact are required',
          headers: {'content-type': 'application/json'});
    }
    final id = await colection.findOne(where.exists("$user.contact.$contact"));

    if (id == null) {
      return Response(400, body: "not exist user $id");
    }

    if (id[user]['contact'] == null) {
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
