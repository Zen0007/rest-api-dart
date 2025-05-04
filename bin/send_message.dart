import 'dart:convert';
import 'server.dart';
import 'package:mongo_dart/mongo_dart.dart';
import 'package:shelf/shelf.dart';

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
        "$sender.contact.$receiver",
        {
          "is_me": sender,
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
        "$receiver.contact.$sender",
        {
          "is_me": sender,
          "text": message,
          "time": date,
        },
      ),
    );

    if (updateSender.isSuccess && updateReceiver.isSuccess) {
      return Response(200, body: "Success send message");
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
