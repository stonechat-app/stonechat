/// Onboarding is the one screen every user sees before they own anything, and
/// it has to survive the keyboard. The layout leans on Spacers to place the
/// wordmark and the footer links, which silently overflows the moment the
/// viewport shrinks — so the rule here is that it must lay out cleanly both
/// with the keyboard up and with the Advanced section expanded.
///
/// (No provider and no core library: AppState is only read when the user taps
/// Create account, which these tests never do.)
library;

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:stonechat/ui/onboarding_screen.dart';

/// Roughly an iPhone 17 Pro; the keyboard takes a little under half of it.
const _screen = Size(402, 874);
const _keyboard = 336.0;

Future<void> _pump(WidgetTester tester, {double bottomInset = 0}) async {
  tester.view.devicePixelRatio = 1.0;
  tester.view.physicalSize = _screen;
  addTearDown(tester.view.reset);

  await tester.pumpWidget(MaterialApp(
    home: MediaQuery(
      data: MediaQueryData(
        size: _screen,
        viewInsets: EdgeInsets.only(bottom: bottomInset),
      ),
      child: const OnboardingScreen(),
    ),
  ));
  await tester.pumpAndSettle();
}

void main() {
  testWidgets('lays out with the keyboard up', (tester) async {
    await _pump(tester, bottomInset: _keyboard);
    expect(tester.takeException(), isNull);

    // The field being typed into has to stay reachable, not just un-overflowed.
    await tester.ensureVisible(find.byType(TextField));
    expect(tester.takeException(), isNull);
  });

  testWidgets('lays out with Advanced expanded', (tester) async {
    await _pump(tester);
    await tester.tap(find.text('Advanced'));
    await tester.pumpAndSettle();

    expect(tester.takeException(), isNull);
    expect(find.textContaining('self-hosters only'), findsOneWidget);
  });

  testWidgets('lays out with both at once', (tester) async {
    await _pump(tester, bottomInset: _keyboard);
    await tester.tap(find.text('Advanced'), warnIfMissed: false);
    await tester.pumpAndSettle();

    expect(tester.takeException(), isNull);
  });
}
