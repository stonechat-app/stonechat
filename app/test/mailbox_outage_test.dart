import 'package:flutter_test/flutter_test.dart';
import 'package:stonechat/state/server_state.dart';

void main() {
  group('formatOutage', () {
    test('reads in minutes below the hour', () {
      expect(formatOutage(const Duration(minutes: 1)), '1m');
      expect(formatOutage(const Duration(minutes: 59)), '59m');
      // Sub-minute rounds down rather than showing "0h" — the strip says
      // "isn't answering · 0m", which is odd but honest.
      expect(formatOutage(const Duration(seconds: 30)), '0m');
    });

    test('switches to hours at the hour and holds through two days', () {
      expect(formatOutage(const Duration(minutes: 60)), '1h');
      expect(formatOutage(const Duration(hours: 2)), '2h');
      expect(formatOutage(const Duration(hours: 47)), '47h');
    });

    test('switches to days at 48h', () {
      expect(formatOutage(const Duration(hours: 48)), '2d');
      expect(formatOutage(const Duration(days: 9, hours: 5)), '9d');
    });

    test('never renders a fractional or negative-looking unit', () {
      for (var m = 0; m < 60 * 24 * 5; m += 7) {
        final s = formatOutage(Duration(minutes: m));
        expect(s, matches(RegExp(r'^\d+[mhd]$')), reason: 'at $m minutes');
      }
    });
  });

  test('the notice threshold outlasts a reboot but not a workday', () {
    // The number itself is a product call; this pins the intent so a casual
    // edit to "5 minutes" (which would fire on every VM restart) or to
    // "3 days" (useless) trips a test.
    expect(ServerState.outageNoticeAfter, greaterThanOrEqualTo(
        const Duration(minutes: 30)));
    expect(ServerState.outageNoticeAfter,
        lessThanOrEqualTo(const Duration(hours: 8)));
  });
}
