// How the app reads GET /v1/access (PROTOCOL.md "Gate"): an open hub needs no
// plan, a gated one needs a tier, and a hub that doesn't say is read as gated.
import 'package:flutter_test/flutter_test.dart';
import 'package:stonechat/core/api.dart';

void main() {
  test('an open hub needs no plan', () {
    final a = HubAccess.fromJson({'gated': false, 'tier': null});
    expect(a.gated, isFalse);
    expect(a.mayProvision, isTrue);
  });

  test('a gated hub without a tier needs one', () {
    final a = HubAccess.fromJson({'gated': true, 'tier': null});
    expect(a.mayProvision, isFalse);
  });

  test('a tier carries its status and the gate\'s notice', () {
    final a = HubAccess.fromJson({
      'gated': true,
      'tier': 'machine',
      'status': 'grace',
      'notice': 'Payment issue',
    });
    expect(a.plan, 'machine');
    expect(a.status, 'grace');
    expect(a.notice, 'Payment issue');
    expect(a.mayProvision, isTrue);
  });

  test('a hub that does not say is read as gated', () {
    final a = HubAccess.fromJson({'tier': null});
    expect(a.gated, isTrue);
    expect(a.mayProvision, isFalse);
  });
}
