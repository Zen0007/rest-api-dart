import 'dart:convert';

import 'package:mongo_dart/mongo_dart.dart';
import 'package:shelf/shelf.dart';

import 'server.dart';


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
    if (id == null) {
      return Response(404, body: "user not found $user");
    }
    final idUser = id["_id"];

    await colection.updateOne(
      where.eq('_id', idUser),
      modify.set(
        "$user.contact.$contact",
        [],
      ),
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
