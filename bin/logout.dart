import 'dart:convert';

import 'package:shelf/shelf.dart';

import 'server.dart';


Future<Response> logout(Request req) async {
  await db.open();
  try {
    final request = await req.readAsString();
    final data = json.decode(request);
    final token = data['exp'];

    if (data.containsKey['exp']) {
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
