/// "Where should your mailbox live?" — the country picker.
///
/// The rest of onboarding deliberately never says "VM", "provider" or
/// "region". Country is the one piece of infrastructure vocabulary a user
/// *does* want, because jurisdiction is what the Mailbox tier sells: the first
/// question a privacy-minded buyer asks is where their mailbox physically
/// sits, and "wherever we put it" is not an answer.
///
/// Two rules this widget exists to enforce:
///
///  1. **Both halves, always.** Every country carries a jurisdiction line and
///     a caveat, and selecting one reveals both. A picker that lists flags and
///     cities is decoration; a picker that says Singapore has broad state
///     access powers is a feature. The hub authors the wording
///     (hub/app/countries.py) so it can be corrected without an app release.
///  2. **No silent placement.** Nothing is selected by default. The user picks,
///     or there is no mailbox — the whole point is that we did not choose.
library;

import 'package:flutter/material.dart';

import '../core/api.dart';
import 'theme.dart';

class CountryPicker extends StatelessWidget {
  final List<MailboxCountry> countries;
  final String? selected; // ISO code, null until the user chooses
  final ValueChanged<String> onSelect;

  /// The account's plan, if known. Countries the plan cannot place into are
  /// shown greyed rather than hidden — "Finland, on the Mailbox plan" is
  /// useful information, and a country vanishing between screens is not.
  final String? plan;
  final bool enabled;

  const CountryPicker({
    super.key,
    required this.countries,
    required this.selected,
    required this.onSelect,
    this.plan,
    this.enabled = true,
  });

  @override
  Widget build(BuildContext context) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        for (final c in countries) ...[
          _CountryRow(
            country: c,
            selected: c.code == selected,
            available: c.allows(plan),
            onTap: enabled && c.allows(plan) ? () => onSelect(c.code) : null,
          ),
          const SizedBox(height: 8),
        ],
      ],
    );
  }
}

class _CountryRow extends StatelessWidget {
  final MailboxCountry country;
  final bool selected;
  final bool available;
  final VoidCallback? onTap;

  const _CountryRow({
    required this.country,
    required this.selected,
    required this.available,
    required this.onTap,
  });

  @override
  Widget build(BuildContext context) {
    return Semantics(
      button: true,
      selected: selected,
      // Screen readers get the caveat too — it is not decoration.
      label: '${country.name}, ${country.city}. '
          '${country.jurisdiction} ${country.caveat}',
      child: InkWell(
        onTap: onTap,
        borderRadius: BorderRadius.circular(Zn.radius),
        child: AnimatedContainer(
          duration: const Duration(milliseconds: 150),
          padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
          decoration: BoxDecoration(
            color: selected ? Zn.orange.withValues(alpha: 0.06) : Zn.raised,
            borderRadius: BorderRadius.circular(Zn.radius),
            border: Border.all(color: selected ? Zn.orange : Zn.line),
          ),
          child: Opacity(
            opacity: available ? 1 : 0.4,
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Row(
                  children: [
                    Text(country.flag, style: const TextStyle(fontSize: 20)),
                    const SizedBox(width: 12),
                    Expanded(
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Text(
                            country.name,
                            style: const TextStyle(
                                color: Zn.text,
                                fontSize: 14.5,
                                fontWeight: FontWeight.w600),
                          ),
                          const SizedBox(height: 1),
                          Text(country.city,
                              style: Zn.mono(size: 11, color: Zn.muted)),
                        ],
                      ),
                    ),
                    if (!available)
                      Text('Machine only',
                          style: Zn.mono(size: 10, color: Zn.muted))
                    else
                      Container(
                        width: 16,
                        height: 16,
                        decoration: BoxDecoration(
                          shape: BoxShape.circle,
                          border: Border.all(
                              color: selected ? Zn.orange : Zn.line,
                              width: 1.5),
                        ),
                        child: selected
                            ? Center(
                                child: Container(
                                  width: 8,
                                  height: 8,
                                  decoration: const BoxDecoration(
                                      color: Zn.orange, shape: BoxShape.circle),
                                ),
                              )
                            : null,
                      ),
                  ],
                ),
                // Expanded only for the chosen country: five caveats at once
                // is a wall of text nobody reads, which defeats the purpose.
                //
                // Built conditionally rather than faded, so the unselected
                // detail is genuinely absent from the tree — a cross-fade
                // leaves it there at zero opacity, which makes "is the caveat
                // shown?" untestable and, worse, still exposed to semantics.
                if (selected)
                  Padding(
                    padding: const EdgeInsets.only(top: 10, left: 32),
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        _Line(
                          mark: '+',
                          color: Zn.ok,
                          text: country.jurisdiction,
                        ),
                        const SizedBox(height: 6),
                        _Line(
                          mark: '!',
                          color: Zn.amber,
                          text: country.caveat,
                        ),
                      ],
                    ),
                  ),
              ],
            ),
          ),
        ),
      ),
    );
  }
}

class _Line extends StatelessWidget {
  final String mark;
  final Color color;
  final String text;

  const _Line({required this.mark, required this.color, required this.text});

  @override
  Widget build(BuildContext context) {
    return Row(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(mark, style: Zn.mono(size: 12, color: color)),
        const SizedBox(width: 8),
        Expanded(
          child: Text(
            text,
            style: const TextStyle(
                color: Zn.muted, fontSize: 12.5, height: 1.45),
          ),
        ),
      ],
    );
  }
}
