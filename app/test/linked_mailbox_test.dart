// A linked device following the directory to a moved mailbox
// (lib/core/linked_mailbox.dart). Regression: the fingerprint signature
// was verified with the key in the directory's own answer, so a hub that
// made up a key, signed any fingerprint with it and returned both moved the
// device wherever it liked. The check is with the identity key this device
// holds — the answer's key never decides.
//
// Core-backed; skips if the library is unavailable in the host test VM.
import 'package:flutter_test/flutter_test.dart';
import 'package:stonechat/core/api.dart' show DirectoryEntry;
import 'package:stonechat/core/crypto.dart';
import 'package:stonechat/core/linked_mailbox.dart';

const _held = 'https://old.example:8443';
const _heldFp = 'b2xkLWZpbmdlcnByaW50';
const _newFp = 'bmV3LWZpbmdlcnByaW50';

void main() {
  CryptoService? me;
  CryptoService? hub;
  setUpAll(() {
    try {
      me = CryptoService.generate();
      hub = CryptoService.generate();
    } catch (_) {
      me = null;
    }
  });

  DirectoryEntry entry(
    CryptoService id, {
    String? stonechatId,
    String address = 'https://new.example:8443',
    String fp = _newFp,
    CryptoService? signer,
    String? sig,
  }) => DirectoryEntry(
    stonechatId: stonechatId ?? id.stonechatId,
    pubkeyB64: id.publicKeyB64,
    mailboxAddress: address,
    mailboxTlsFp: fp,
    mailboxTlsSig: sig ?? (signer ?? id).signTlsFp(fp),
  );

  String? why;
  ({String address, String tlsFp})? move(CryptoService id, DirectoryEntry e) {
    why = null;
    return linkedMailboxMove(
      e,
      askedFor: id.stonechatId,
      identityPubkeyB64: id.publicKeyB64,
      heldAddress: _held,
      heldTlsFp: _heldFp,
      vouchedByIdentity: (fp, sig) => id.verifyTlsSig(fp, sig, id.publicKey),
      reason: (r) => why = r,
    );
  }

  test('a move our identity signed is followed', () {
    final id = me;
    if (id == null) return markTestSkipped('core unavailable in test VM');
    expect(
      move(id, entry(id)),
      (address: 'https://new.example:8443', tlsFp: _newFp),
    );
    expect(why, isNull);
  });

  test('the same coordinates are no move', () {
    final id = me;
    if (id == null) return markTestSkipped('core unavailable in test VM');
    expect(move(id, entry(id, address: _held, fp: _heldFp)), isNull);
    expect(why, isNull);
  });

  test("a hub's self-consistent record under its own key is refused", () {
    final id = me, h = hub;
    if (id == null || h == null) return markTestSkipped('core unavailable');
    // Internally perfect: the signature verifies under the key in the answer.
    final forged = entry(h, stonechatId: id.stonechatId, signer: h);
    expect(h.verifyTlsSig(_newFp, forged.mailboxTlsSig!, h.publicKey), isTrue);
    expect(move(id, forged), isNull);
    expect(why, contains('another identity'));
  });

  test('our key over a fingerprint somebody else signed is refused', () {
    final id = me, h = hub;
    if (id == null || h == null) return markTestSkipped('core unavailable');
    expect(move(id, entry(id, signer: h)), isNull);
    expect(why, contains('not signed by our identity'));
    expect(move(id, entry(id, sig: 'bm90IGEgc2ln')), isNull);
  });

  test("somebody else's whole record is refused", () {
    final id = me, h = hub;
    if (id == null || h == null) return markTestSkipped('core unavailable');
    expect(move(id, entry(h)), isNull);
    expect(why, contains('another identity'));
  });

  test('a signed move to anything but https is refused', () {
    final id = me;
    if (id == null) return markTestSkipped('core unavailable in test VM');
    expect(move(id, entry(id, address: 'http://new.example:8443')), isNull);
    expect(why, contains('https'));
    expect(move(id, entry(id, address: 'new.example:8443')), isNull);
  });

  test('a record with no mailbox is not a move', () {
    final id = me;
    if (id == null) return markTestSkipped('core unavailable in test VM');
    final e = DirectoryEntry(
      stonechatId: id.stonechatId,
      pubkeyB64: id.publicKeyB64,
    );
    expect(move(id, e), isNull);
    expect(why, isNull);
  });
}
