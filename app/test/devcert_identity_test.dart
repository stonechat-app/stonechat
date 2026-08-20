/// Regression: a certificate minted under a *previous* identity must not be
/// kept. It is unexpired and well-formed, so freshness alone cannot reject it
/// — and publishing it makes every peer see a forged signature while nothing
/// looks wrong on this device.
import 'package:flutter_test/flutter_test.dart';
import 'package:stonechat/core/device_keys.dart';

Map<String, dynamic> cert(String id, {int daysLeft = 120}) => {
      'stonechat_id': id,
      'device_id': 1,
      'sig_pub': 'AA==',
      'seal_pub': 'AA==',
      'not_after':
          DateTime.now().toUtc().add(Duration(days: daysLeft)).millisecondsSinceEpoch ~/
              1000,
      'sig': 'AA==',
    };

void main() {
  test('a fresh certificate for this identity is kept', () {
    expect(certNeedsReminting(cert('SC-AAAA'), 'SC-AAAA'), isFalse);
  });

  test('a certificate from a previous identity is re-minted', () {
    final other = cert('SC-BBBB');
    // The point of the test: by every other measure this certificate is good.
    expect(certNeedsRefresh(other), isFalse);
    expect(certNeedsReminting(other, 'SC-AAAA'), isTrue);
  });

  test('no certificate, or no identity yet, means mint', () {
    expect(certNeedsReminting(null, 'SC-AAAA'), isTrue);
    expect(certNeedsReminting(cert('SC-AAAA'), null), isTrue);
  });

  test('expiry still forces a re-mint for the right identity', () {
    expect(certNeedsReminting(cert('SC-AAAA', daysLeft: 2), 'SC-AAAA'), isTrue);
  });
}
