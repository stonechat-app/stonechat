// Fan-out concurrency (TODO.md §1, MULTIDEVICE.md "Why not let the relay fan
// out?"). Group sends were one round trip per member end to end; multi-device
// multiplies that by the recipient's device count, so the loop had to go.
//
// These two primitives are where the correctness lives: runBounded must not
// exceed its budget or reorder results, and KeyedSerializer must never let two
// operations on one ratchet overlap.
import 'package:flutter_test/flutter_test.dart';
import 'package:stonechat/state/chat_state.dart';

/// Completes after [ms] of *fake* time — these tests run inside
/// `fakeAsync`-free real time, so keep the delays tiny and rely on ordering,
/// not on wall-clock precision.
Future<void> tick([int ms = 1]) => Future<void>.delayed(Duration(milliseconds: ms));

void main() {
  group('runBounded', () {
    test('returns results in task order, not completion order', () async {
      // Task 0 finishes last; its result must still come first.
      final results = await runBounded<int>(4, [
        () async {
          await tick(20);
          return 0;
        },
        () async {
          await tick(1);
          return 1;
        },
        () async => 2,
      ]);
      expect(results, [0, 1, 2]);
    });

    test('never exceeds the limit', () async {
      var inFlight = 0;
      var peak = 0;
      await runBounded<void>(3, [
        for (var i = 0; i < 20; i++)
          () async {
            inFlight++;
            peak = peak > inFlight ? peak : inFlight;
            await tick(2);
            inFlight--;
          },
      ]);
      expect(peak, lessThanOrEqualTo(3));
      expect(inFlight, 0, reason: 'every task must have finished');
    });

    test('actually runs concurrently — the whole point', () async {
      var peak = 0;
      var inFlight = 0;
      await runBounded<void>(5, [
        for (var i = 0; i < 5; i++)
          () async {
            inFlight++;
            peak = peak > inFlight ? peak : inFlight;
            await tick(5);
            inFlight--;
          },
      ]);
      expect(peak, greaterThan(1),
          reason: 'a serial implementation would peak at 1');
    });

    test('runs every task even when there are more than the limit', () async {
      final seen = <int>[];
      await runBounded<void>(2, [
        for (var i = 0; i < 25; i++)
          () async {
            await tick();
            seen.add(i);
          },
      ]);
      expect(seen.length, 25);
      expect(seen.toSet().length, 25, reason: 'no task may run twice');
    });

    test('degenerate inputs', () async {
      expect(await runBounded<int>(4, []), isEmpty);
      // A limit below 1 must still make progress rather than hanging.
      expect(await runBounded<int>(0, [() async => 7]), [7]);
      expect(await runBounded<int>(-3, [() async => 7]), [7]);
      // A limit above the task count is fine.
      expect(await runBounded<int>(99, [() async => 1, () async => 2]), [1, 2]);
    });
  });

  group('KeyedSerializer', () {
    test('never overlaps two operations on the same key', () async {
      final s = KeyedSerializer();
      var inFlight = 0;
      var overlapped = false;
      await Future.wait([
        for (var i = 0; i < 8; i++)
          s.run('peer-A', () async {
            if (inFlight > 0) overlapped = true;
            inFlight++;
            await tick(2);
            inFlight--;
          }),
      ]);
      expect(overlapped, isFalse,
          reason: 'two encrypts on one ratchet would reuse a message key');
    });

    test('preserves submission order within a key', () async {
      final s = KeyedSerializer();
      final order = <int>[];
      await Future.wait([
        for (var i = 0; i < 5; i++)
          s.run('peer-A', () async {
            // Descending delays: a non-serializing implementation would let
            // the later, faster bodies finish first.
            await tick(10 - i);
            order.add(i);
          }),
      ]);
      expect(order, [0, 1, 2, 3, 4]);
    });

    test('different keys proceed in parallel', () async {
      final s = KeyedSerializer();
      var inFlight = 0;
      var peak = 0;
      await Future.wait([
        for (var i = 0; i < 6; i++)
          s.run('peer-$i', () async {
            inFlight++;
            peak = peak > inFlight ? peak : inFlight;
            await tick(5);
            inFlight--;
          }),
      ]);
      expect(peak, greaterThan(1),
          reason: 'serializing across peers would defeat concurrent fan-out');
    });

    test('a failure does not wedge the key', () async {
      // One unreachable peer must not block every later message to them.
      final s = KeyedSerializer();
      await expectLater(
        s.run<void>('peer-A', () async => throw StateError('mailbox down')),
        throwsStateError,
      );
      expect(await s.run<int>('peer-A', () async => 42), 42);
    });

    test('propagates the body result and its errors to the caller', () async {
      final s = KeyedSerializer();
      expect(await s.run<String>('k', () async => 'ok'), 'ok');
      await expectLater(
        s.run<String>('k', () async => throw ArgumentError('nope')),
        throwsArgumentError,
      );
    });
  });

  test('fanOutConcurrency is bounded and greater than one', () {
    // Pinned: 1 would be the serial behaviour this replaced, and an unbounded
    // value would open a socket per member on a phone radio.
    expect(fanOutConcurrency, greaterThan(1));
    expect(fanOutConcurrency, lessThanOrEqualTo(16));
  });
}
