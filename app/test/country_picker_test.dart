/// The country picker's one load-bearing rule: a selected country shows its
/// caveat, not just its jurisdiction. Everything else about this widget is
/// cosmetic and may change freely; that rule is the feature.
///
/// (First widget test in the app — `flutter_test`'s WidgetTester needs no
/// extra setup, and this needs no core library because it touches no crypto.)
library;

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:stonechat/core/api.dart';
import 'package:stonechat/ui/country_picker.dart';

MailboxCountry _country({
  String code = 'SG',
  List<String> plans = const ['sovereign'],
}) =>
    MailboxCountry(
      code: code,
      name: 'Singapore',
      city: 'Singapore',
      flag: '🇸🇬',
      jurisdiction: 'Best connectivity in Southeast Asia.',
      caveat: 'Broad state access powers, including compelled decryption.',
      plans: plans,
    );

Widget _host(Widget child) =>
    MaterialApp(home: Scaffold(body: SingleChildScrollView(child: child)));

void main() {
  testWidgets('a selected country shows its caveat alongside its jurisdiction',
      (tester) async {
    await tester.pumpWidget(_host(CountryPicker(
      countries: [_country()],
      selected: 'SG',
      onSelect: (_) {},
    )));
    await tester.pumpAndSettle();

    expect(find.textContaining('Best connectivity'), findsOneWidget);
    // The half a marketing-minded refactor would drop.
    expect(find.textContaining('compelled decryption'), findsOneWidget);
  });

  testWidgets('nothing is selected by default, so we never pick for the user',
      (tester) async {
    await tester.pumpWidget(_host(CountryPicker(
      countries: [_country()],
      selected: null,
      onSelect: (_) {},
    )));
    await tester.pumpAndSettle();

    // Collapsed: the country is offered, its detail is not yet asserted.
    expect(find.text('Singapore'), findsWidgets);
    expect(find.textContaining('compelled decryption'), findsNothing);
  });

  testWidgets('tapping reports the country code', (tester) async {
    String? picked;
    await tester.pumpWidget(_host(CountryPicker(
      countries: [_country()],
      selected: null,
      onSelect: (c) => picked = c,
    )));
    await tester.tap(find.text('Singapore').first);
    expect(picked, 'SG');
  });

  testWidgets('a country the plan cannot place is shown but not selectable',
      (tester) async {
    var taps = 0;
    await tester.pumpWidget(_host(CountryPicker(
      countries: [_country(plans: const ['sovereign'])],
      selected: null,
      plan: 'private',
      onSelect: (_) => taps++,
    )));

    // Visible on purpose — "Finland, but not on your plan" is information;
    // a country that vanishes between screens is confusing.
    expect(find.text('Singapore'), findsWidgets);
    expect(find.text('Sovereign only'), findsOneWidget);
    await tester.tap(find.text('Singapore').first);
    expect(taps, 0);
  });
}
