import 'package:enough_mail/enough_mail.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:openpgp/openpgp.dart';
import 'package:flutter/services.dart' show rootBundle;

void main() {
  test('Decrypt an encrypted and signed mime-message', () async {
    final text = await rootBundle
        .loadString('integration_test/pgp/pgp-mime-enc-sign-attach.eml');
    final key = await rootBundle
        .loadString('integration_test/pgp/Kira (E291CC36) – Geheim.asc');
    final publicKey = await rootBundle
        .loadString('integration_test/pgp/Tallinn (E057D981) – Öffentlich.asc');
    await testIt(text, key, publicKey, '123456');
  });

  test('Decrypt an encrypted and signed mime-message, full keyrings', () async {
    final text = await rootBundle
        .loadString('integration_test/pgp/pgp-mime-enc-sign-attach.eml');
    final keys =
    await rootBundle.loadString('integration_test/pgp/private.asc');
    final publicKeys =
    await rootBundle.loadString('integration_test/pgp/public.asc');
    await testIt(text, keys, publicKeys, '123456');
  });
}

Future<void> testIt(
    final String text, String key, String publicKey, String password) async {
  final String result = await testDecryption(text, key, password);
  expect(result, isNotNull);
  final bool isValid = await testVerify(result, publicKey);
  expect(isValid, equals(true));
}

Future<bool> testVerify(String text, String publicKey) async {
  try {
    final message = MimeMessage.parseFromText(text);
    expect(message, isNotNull);
    expect(message.getHeaderContentType()?.mediaType.text,
        equals('multipart/signed'));
    final signedPart = message.parts?[0];
    final signedData = (signedPart?.mimeData as TextMimeData?)?.text;
    final signature = message.parts?[1].decodeContentText();
    expect(signedData, isNotNull);
    expect(signature, isNotNull);
    final isValid = await OpenPGP.verify(
        signature!, '${signedData!.trimRight()}\r\n', publicKey);
    return isValid;
  } on OpenPGPException catch (e) {
    fail("OpenPGPException: ${e.cause}");
  }
}

enum EncryptionType { rfcPGPMime, brokenEvolutionPGPMime, pgpInline, none }

EncryptionType determineEncryptionType(MimeMessage message) {
  if ((message.getHeaderContentType()?.mediaType.text ==
          "multipart/encrypted") &&
      (message.getHeaderContentType()?.parameters["protocol"] ==
          "application/pgp-encrypted") &&
      (message.parts?[0].getHeaderContentType()?.mediaType.text ==
          "application/pgp-encrypted")) {
    return EncryptionType.rfcPGPMime;
  }
  // Older versions of Evolution defect from the standard by presenting a pgp-mime-encrypted
  // message as "multipart/mixed" with the application/pgp-encrypted part not being
  // the first but the second one.
  if ((message.getHeaderContentType()?.mediaType.text == "multipart/mixed") &&
      ((message.parts?.length ?? 0) > 1) &&
      (message.parts?[1].getHeaderContentType()?.mediaType.text ==
          "application/pgp-encrypted")) {
    return EncryptionType.brokenEvolutionPGPMime;
  }
  //TODO: identify PGP-INLINE
  return EncryptionType.none;
}

String? getEncryptedText(MimeMessage message) {
  switch (determineEncryptionType(message)) {
    case EncryptionType.pgpInline:
      //TODO: HANDLE PGPINLINE
      return null;
    case EncryptionType.none:
      return null;
    case EncryptionType.rfcPGPMime:
      return message.parts?.elementAt(1).decodeContentText();
    case EncryptionType.brokenEvolutionPGPMime:
      return message.parts?.elementAt(2).decodeContentText();
  }
}

Future<String> testDecryption(String text, String key, String password) async {
  try {
    final message = MimeMessage.parseFromText(text);
    final body = getEncryptedText(message);
    expect(body, isNotNull);
    final result = await OpenPGP.decrypt(body!, key, password);
    return result;
  } on OpenPGPException catch (e) {
    fail("OpenPGPException: ${e.cause}");
  }
}
