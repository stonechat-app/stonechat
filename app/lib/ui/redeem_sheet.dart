/// Bottom sheet for redeeming a STONECHAT-XXXX-XXXX activation code — the moment
/// a landing-page purchase (or a comp grant) gets bound to this Stonechat ID.
library;

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:provider/provider.dart';

import '../core/api.dart';
import '../state/app_state.dart';
import 'theme.dart';
import 'widgets.dart';

/// Returns true if a plan was activated.
Future<bool> showRedeemSheet(BuildContext context) async {
  final activated = await showModalBottomSheet<bool>(
    context: context,
    backgroundColor: Zn.surface,
    isScrollControlled: true, // keyboard pushes the sheet up
    shape: const RoundedRectangleBorder(
      borderRadius: BorderRadius.vertical(top: Radius.circular(8)),
    ),
    builder: (_) => const _RedeemSheet(),
  );
  return activated ?? false;
}

class _RedeemSheet extends StatefulWidget {
  const _RedeemSheet();

  @override
  State<_RedeemSheet> createState() => _RedeemSheetState();
}

class _RedeemSheetState extends State<_RedeemSheet> {
  final _code = TextEditingController();
  bool _busy = false;
  String? _error;

  @override
  void dispose() {
    _code.dispose();
    super.dispose();
  }

  Future<void> _redeem() async {
    final code = _code.text.trim();
    if (code.isEmpty) return;
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      final result =
          await context.read<AppState>().api.redeemCode(code);
      if (!mounted) return;
      Navigator.pop(context, true);
      final plan = result.plan == 'machine' ? 'Machine' : 'Mailbox';
      showZnSnack(context, '$plan plan activated');
    } on ApiException catch (e) {
      setState(() {
        _busy = false;
        _error = e.message;
      });
    } catch (_) {
      setState(() {
        _busy = false;
        _error = "Couldn't reach the mailbox — try again";
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: EdgeInsets.only(
        left: 24,
        right: 24,
        top: 20,
        bottom: 20 + MediaQuery.of(context).viewInsets.bottom,
      ),
      child: Column(
        mainAxisSize: MainAxisSize.min,
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text('REDEEM ACTIVATION CODE',
              style: Zn.mono(size: 10, letterSpacing: 2)),
          const SizedBox(height: 12),
          const Text(
            'Bought a plan on stonechat.app? Enter the code from the '
            'success page or your receipt.',
            style: TextStyle(color: Zn.muted, fontSize: 13, height: 1.4),
          ),
          const SizedBox(height: 16),
          TextField(
            controller: _code,
            autofocus: true,
            enabled: !_busy,
            textCapitalization: TextCapitalization.characters,
            inputFormatters: [
              TextInputFormatter.withFunction((oldValue, newValue) =>
                  newValue.copyWith(text: newValue.text.toUpperCase())),
            ],
            style: Zn.mono(size: 16, color: Zn.text, letterSpacing: 2),
            decoration: InputDecoration(
              hintText: 'STONECHAT-XXXX-XXXX',
              hintStyle: Zn.mono(size: 16, letterSpacing: 2),
              errorText: _error,
            ),
            onSubmitted: (_) => _redeem(),
          ),
          const SizedBox(height: 16),
          SizedBox(
            width: double.infinity,
            height: 46,
            child: FilledButton(
              onPressed: _busy ? null : _redeem,
              child: _busy
                  ? const SizedBox(
                      width: 16,
                      height: 16,
                      child: CircularProgressIndicator(strokeWidth: 2))
                  : const Text('Activate'),
            ),
          ),
        ],
      ),
    );
  }
}
