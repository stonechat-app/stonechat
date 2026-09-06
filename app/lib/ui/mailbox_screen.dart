import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../core/api.dart';
import '../state/app_state.dart';
import '../state/mailbox_state.dart';
import 'country_picker.dart';
import 'redeem_sheet.dart';
import 'theme.dart';
import 'widgets.dart';

/// Machine settings are an implementation detail now: each provider gets its
/// fixed sensible default, nothing is user-editable.
const _providerDefaults = {
  'gcp': (machineType: 'e2-micro', region: 'us-central1-a'),
  'aws': (machineType: 't3.micro', region: 'us-east-1'),
  'digitalocean': (machineType: 's-1vcpu-1gb', region: 'fra1'),
  'hetzner': (machineType: 'cx22', region: 'fsn1'),
  'vultr': (machineType: 'vc2-1c-1gb', region: 'sao'),
  'fleet': (machineType: 'container', region: 'shared'),
  'local': (machineType: 'container', region: 'localhost'),
};

const _providerLabels = {
  'gcp': 'Stonechat Cloud · dedicated',
  'aws': 'Stonechat Cloud · dedicated',
  'digitalocean': 'Stonechat Cloud · dedicated',
  'hetzner': 'Stonechat Cloud · dedicated',
  'vultr': 'Stonechat Cloud · dedicated',
  'fleet': 'Stonechat Cloud',
  'local': 'This computer',
  'external': 'Self-hosted',
};

/// The three ways to get a mailbox.
enum _Choice { cloud, friend, selfHost }

class MailboxScreen extends StatefulWidget {
  const MailboxScreen({super.key});

  @override
  State<MailboxScreen> createState() => _MailboxScreenState();
}

class _MailboxScreenState extends State<MailboxScreen> {
  _Choice _choice = _Choice.cloud;
  // Which card's action is in flight. Drives that button's spinner and
  // freezes the other cards — switching options mid-provision would fire a
  // second mailbox request on top of the running one.
  _Choice? _pending;
  final _inviteInput = TextEditingController();
  final _extAddress = TextEditingController();
  final _extToken = TextEditingController();
  String? _plan; // live entitlement plan, for the invites entry
  /// Null while the catalog is in flight; empty when the hub cannot answer.
  /// Same three states the setup screen distinguishes, for the same reason:
  /// "still loading" and "this hub has no catalog" must not both fall through
  /// to placing a mailbox nobody chose the location of.
  List<MailboxCountry>? _countries;
  String? _country; // deliberately null: we never pick a jurisdiction for you

  @override
  void initState() {
    super.initState();
    _loadPlan();
    _loadCountries();
  }

  Future<void> _loadCountries() async {
    try {
      final list = await context.read<AppState>().api.getCountries();
      if (mounted) setState(() => _countries = list);
    } catch (_) {
      // Non-fatal: this screen still has to work against a hub that is down
      // or older than the catalog.
      if (mounted) setState(() => _countries = const []);
    }
  }

  Future<void> _loadPlan() async {
    try {
      final e = await context.read<AppState>().api.getEntitlement();
      if (mounted) setState(() => _plan = e?.plan);
    } on Exception {
      // best-effort; the invites entry also keys off the provider
    }
  }

  /// Machine plans and self-hosters can host friends' mailboxes.
  bool _canHostFriends(MailboxState mailbox) {
    if (!mailbox.isRunning) return false;
    final p = mailbox.record.provider;
    return mailbox.isExternal ||
        p == 'gcp' ||
        p == 'aws' ||
        _plan == 'machine' ||
        (kDebugMode && p == 'local');
  }

  /// Which card a live mailbox record lights up. Friend-hosted and self-hosted
  /// mailboxes are both `external` records on the hub; the locally-stored
  /// friend-hosted flag (AppState) tells them apart.
  _Choice _activeChoice(MailboxState mailbox) => mailbox.isFriendHosted
      ? _Choice.friend
      : mailbox.isExternal
          ? _Choice.selfHost
          : _Choice.cloud;

  void _lockedNotice() {
    showZnSnack(
        context, 'Turn off your current mailbox before starting a new one.');
  }

  @override
  Widget build(BuildContext context) {
    final mailbox = context.watch<MailboxState>();
    // A mailbox exists (running, setting up, or errored): the choice cards
    // stay visible so the other options are discoverable, but they're locked —
    // the live one is marked, the rest are dimmed and tapping them explains.
    final locked = mailbox.record.status != 'none';
    final active = locked ? _activeChoice(mailbox) : null;

    return Scaffold(
      appBar: AppBar(
        title: const Text('Your mailbox',
            style: TextStyle(fontSize: 17, fontWeight: FontWeight.w600)),
      ),
      body: ListView(
        padding: const EdgeInsets.all(20),
        children: [
          _StatusCard(mailbox: mailbox),
          const SizedBox(height: 20),
          if (!locked) ...[
            const Text(
              'Your mailbox receives messages when your phone is offline. '
              'It holds only encrypted envelopes — each one is deleted the '
              'moment your phone picks it up.',
              style: TextStyle(color: Zn.muted, fontSize: 13, height: 1.45),
            ),
            const SizedBox(height: 20),
          ],
          ZnOptionCard(
            title: 'Stonechat Cloud',
            subtitle: 'We run it for you. Nothing to set up — '
                'ready in about two minutes.',
            selected: !locked && _choice == _Choice.cloud,
            active: active == _Choice.cloud,
            dimmed: locked && active != _Choice.cloud,
            onTap: locked
                ? (active == _Choice.cloud ? null : _lockedNotice)
                : (_pending != null
                    ? null
                    : () => setState(() => _choice = _Choice.cloud)),
            children: [
              // The same choice onboarding offers. It lived only there, so a
              // mailbox turned on from this screen was placed for the user
              // without them ever seeing the question — the one outcome the
              // whole feature exists to prevent.
              ..._countryChooser(mailbox.busy || _pending != null),
              SizedBox(
                width: double.infinity,
                height: 48,
                child: FilledButton(
                  onPressed: mailbox.busy ? null : () => _createCloud(mailbox),
                  child: _pending == _Choice.cloud
                      ? const SizedBox(
                          width: 18,
                          height: 18,
                          child: CircularProgressIndicator(strokeWidth: 2))
                      : const Text('Turn on my mailbox'),
                ),
              ),
            ],
          ),
          const SizedBox(height: 10),
          ZnOptionCard(
            title: "A friend's machine",
            subtitle: 'Someone you trust hosts your mailbox on their '
                'mailbox. You just need their invite.',
            selected: !locked && _choice == _Choice.friend,
            active: active == _Choice.friend,
            dimmed: locked && active != _Choice.friend,
            onTap: locked
                ? (active == _Choice.friend ? null : _lockedNotice)
                : (_pending != null
                    ? null
                    : () => setState(() => _choice = _Choice.friend)),
            children: [
              const Text(
                'Your messages stay end-to-end encrypted — but your host '
                'can see that your mailbox is there and its traffic '
                'timing. Only accept from someone you trust with that.',
                style:
                    TextStyle(color: Zn.muted, fontSize: 12.5, height: 1.45),
              ),
              const SizedBox(height: 12),
              ZnLabeledField(
                  label: 'Paste the invite here',
                  controller: _inviteInput),
              const SizedBox(height: 12),
              SizedBox(
                width: double.infinity,
                height: 44,
                child: FilledButton(
                  onPressed: mailbox.busy ? null : () => _joinHost(mailbox),
                  child: _pending == _Choice.friend
                      ? const Row(
                          mainAxisSize: MainAxisSize.min,
                          children: [
                            SizedBox(
                                width: 18,
                                height: 18,
                                child:
                                    CircularProgressIndicator(strokeWidth: 2)),
                            SizedBox(width: 10),
                            Flexible(
                                child: Text(
                                    'Setting up on your friend\'s mailbox…',
                                    maxLines: 1,
                                    overflow: TextOverflow.ellipsis)),
                          ],
                        )
                      : const Text('Join with invite'),
                ),
              ),
            ],
          ),
          const SizedBox(height: 10),
          ZnOptionCard(
            title: 'Self-host',
            subtitle: 'Run the relay on your own machine. '
                'Free, forever.',
            selected: !locked && _choice == _Choice.selfHost,
            active: active == _Choice.selfHost,
            dimmed: locked && active != _Choice.selfHost,
            onTap: locked
                ? (active == _Choice.selfHost ? null : _lockedNotice)
                : (_pending != null
                    ? null
                    : () => setState(() => _choice = _Choice.selfHost)),
            children: [
              const Text(
                'Run the Stonechat mailbox anywhere you like, then connect it '
                'here. Its access token stays on this phone — we only list '
                'the address so friends can find you.',
                style:
                    TextStyle(color: Zn.muted, fontSize: 12.5, height: 1.45),
              ),
              const SizedBox(height: 12),
              ZnLabeledField(label: 'Address', controller: _extAddress),
              const SizedBox(height: 12),
              ZnLabeledField(label: 'Mailbox token', controller: _extToken),
              const SizedBox(height: 12),
              SizedBox(
                width: double.infinity,
                height: 44,
                child: FilledButton(
                  onPressed:
                      mailbox.busy ? null : () => _connectExternal(mailbox),
                  child: _pending == _Choice.selfHost
                      ? const SizedBox(
                          width: 18,
                          height: 18,
                          child: CircularProgressIndicator(strokeWidth: 2))
                      : const Text('Connect my mailbox'),
                ),
              ),
            ],
          ),
          const SizedBox(height: 10),
          if (mailbox.isProvisioning)
            const Padding(
              padding: EdgeInsets.only(top: 8),
              child: Text(
                'Setting up your mailbox — this takes about 2 minutes the '
                "first time. You can leave this screen; we'll notify you "
                "when it's ready.",
                style: TextStyle(color: Zn.muted, fontSize: 12.5, height: 1.4),
              ),
            ),
          if (_canHostFriends(mailbox)) ...[
            _InvitesEntry(
                onTap: () => Navigator.pushNamed(context, '/invites')),
            const SizedBox(height: 12),
          ],
          if (mailbox.isRunning || mailbox.record.status == 'error') ...[
            const SizedBox(height: 8),
            SizedBox(
              width: double.infinity,
              height: 48,
              child: OutlinedButton(
                style: OutlinedButton.styleFrom(
                  foregroundColor: Zn.danger,
                  side: const BorderSide(color: Zn.danger),
                ),
                onPressed: mailbox.busy ? null : () => _destroy(mailbox),
                child: mailbox.busy
                    ? Row(
                        mainAxisSize: MainAxisSize.min,
                        children: [
                          const SizedBox(
                            width: 16,
                            height: 16,
                            child: CircularProgressIndicator(
                                strokeWidth: 2, color: Zn.danger),
                          ),
                          const SizedBox(width: 10),
                          Text(mailbox.isExternal
                              ? 'Disconnecting…'
                              : 'Turning off…'),
                        ],
                      )
                    : Text(mailbox.isExternal
                        ? 'Disconnect mailbox'
                        : 'Turn off mailbox'),
              ),
            ),
            const SizedBox(height: 8),
            Text(
              mailbox.isExternal
                  ? 'Disconnecting removes your address from the directory — '
                      'your mailbox keeps running and is yours to stop. Your '
                      'chat history on this phone is never affected.'
                  : 'While your mailbox is off you won\'t receive messages — '
                      'they\'ll wait on your friends\' phones and arrive once '
                      'you turn it back on. Your chat history on this phone '
                      'is never affected.',
              style: const TextStyle(color: Zn.muted, fontSize: 12.5, height: 1.4),
            ),
          ],
        ],
      ),
    );
  }

  // In debug builds default to a local Docker mailbox so development never
  // needs a cloud account; release builds pick the provider the account's
  // plan entitles it to (PROTOCOL.md "Billing"): mailbox → fleet,
  // machine → gcp. --dart-define=STONECHAT_PROVIDER overrides everything.
  static const _envProvider = String.fromEnvironment('STONECHAT_PROVIDER');

  /// null → no plan on this account yet (caller offers the redeem sheet).
  Future<String?> _resolveProvider() async {
    if (_envProvider != '') return _envProvider;
    if (kDebugMode) return 'local';
    final entitlement = await context.read<AppState>().api.getEntitlement();
    if (entitlement == null) return null;
    return entitlement.plan == 'machine' ? 'gcp' : 'fleet';
  }

  /// The picker, plus the framing that must travel with it.
  ///
  /// Empty while the catalog is loading or when the hub has none, so a hub
  /// that cannot answer leaves the card exactly as it was before the picker
  /// existed rather than showing an empty list.
  List<Widget> _countryChooser(bool busy) {
    final countries = _countries;
    if (countries == null || countries.isEmpty) return const [];
    return [
      Text(
        'Where should it live?',
        style: TextStyle(
            color: Zn.text, fontSize: 14, fontWeight: FontWeight.w600),
      ),
      const SizedBox(height: 6),
      Text(
        'Your mailbox only ever holds encrypted messages, so this choice '
        "doesn't decide who can read them — nobody can. It decides whose "
        'laws apply to the machine, and who could seize it.',
        style: TextStyle(color: Zn.muted, fontSize: 12.5, height: 1.45),
      ),
      const SizedBox(height: 12),
      CountryPicker(
        countries: countries,
        selected: _country,
        // Countries this plan cannot place into are greyed, not hidden:
        // "Finland, on the Machine plan" is useful, and a country vanishing
        // between screens is not.
        plan: _plan,
        enabled: !busy,
        onSelect: (code) => setState(() => _country = code),
      ),
      const SizedBox(height: 14),
    ];
  }

  Future<void> _createCloud(MailboxState mailbox) async {
    setState(() => _pending = _Choice.cloud);
    try {
      var provider = await _resolveProvider();
      if (provider == null) {
        if (!mounted) return;
        final activated = await showRedeemSheet(context);
        provider = activated && mounted ? await _resolveProvider() : null;
        if (provider == null) return;
      }
      if (_countries == null) {
        // Catalog still in flight. Refusing beats falling through to the
        // fallback below, which would place the mailbox without a choice.
        if (mounted) showZnSnack(context, 'Still loading locations…');
        return;
      }
      if (_countries!.isEmpty) {
        // Hub unreachable or older than the catalog: degrade to the plan →
        // provider mapping this screen used before the picker existed, so a
        // stale hub means "no country choice" rather than "no mailbox".
        final d = _providerDefaults[provider] ?? _providerDefaults['gcp']!;
        await mailbox.create(
          provider: provider,
          machineType: d.machineType,
          region: d.region,
        );
        _loadPlan();
        return;
      }
      if (_country == null) {
        if (mounted) {
          showZnSnack(context, 'Choose where your mailbox should live first');
        }
        return;
      }
      await mailbox.create(country: _country);
      _loadPlan();
    } on ApiException catch (e) {
      if (!mounted) return;
      if (e.code == 'subscription_required') {
        // Belt and braces: the mailbox re-checks the entitlement (it may have
        // lapsed since we looked). Offer the code path and retry.
        final activated = await showRedeemSheet(context);
        if (activated && mounted) await _createCloud(mailbox);
      } else {
        showZnSnack(context, '$e', error: true);
      }
    } catch (e) {
      if (mounted) showZnSnack(context, '$e', error: true);
    } finally {
      if (mounted) setState(() => _pending = null);
    }
  }

  Future<void> _connectExternal(MailboxState mailbox) async {
    final address = _extAddress.text.trim();
    final token = _extToken.text.trim();
    if (address.isEmpty || token.isEmpty) {
      showZnSnack(context, 'Enter your mailbox address and token', error: true);
      return;
    }
    setState(() => _pending = _Choice.selfHost);
    try {
      await mailbox.connectExternal(address, token);
      if (mounted) showZnSnack(context, 'Connected — friends can reach you now');
    } catch (e) {
      if (mounted) showZnSnack(context, '$e', error: true);
    } finally {
      if (mounted) setState(() => _pending = null);
    }
  }

  Future<void> _joinHost(MailboxState mailbox) async {
    final invite = _inviteInput.text.trim();
    if (invite.isEmpty) {
      showZnSnack(context, 'Paste the invite first', error: true);
      return;
    }
    setState(() => _pending = _Choice.friend);
    try {
      await mailbox.joinHost(invite);
      if (mounted) {
        showZnSnack(context, 'Joined — your mailbox is live on your friend\'s host');
      }
    } catch (e) {
      if (mounted) showZnSnack(context, '$e', error: true);
    } finally {
      if (mounted) setState(() => _pending = null);
    }
  }

  Future<void> _destroy(MailboxState mailbox) async {
    final external = mailbox.isExternal;
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        backgroundColor: Zn.surface,
        title: Text(external
            ? 'Disconnect your mailbox?'
            : 'Turn off your mailbox?'),
        content: Text(
            external
                ? 'Your address is removed from the directory; the mailbox '
                    'itself keeps running and stays yours. Your chat history '
                    'stays on this phone.'
                : 'You\'ll stop receiving messages until you turn it back on. '
                    'New messages will wait on your friends\' phones. Your '
                    'chat history stays on this phone.',
            style: const TextStyle(color: Zn.muted, height: 1.4)),
        actions: [
          TextButton(
              onPressed: () => Navigator.pop(context, false),
              child: Text(external ? 'Stay connected' : 'Keep it on')),
          TextButton(
              onPressed: () => Navigator.pop(context, true),
              child: Text(external ? 'Disconnect' : 'Turn off',
                  style: const TextStyle(color: Zn.danger))),
        ],
      ),
    );
    if (confirmed != true) return;
    try {
      await mailbox.destroy();
      if (mounted) {
        showZnSnack(context,
            external ? 'Mailbox disconnected' : 'Mailbox turned off');
      }
    } catch (e) {
      if (mounted) showZnSnack(context, '$e', error: true);
    }
  }
}

class _StatusCard extends StatelessWidget {
  final MailboxState mailbox;
  const _StatusCard({required this.mailbox});

  @override
  Widget build(BuildContext context) {
    final r = mailbox.record;
    final (color, headline) = switch (r.status) {
      // busy while running can only be the teardown call — surface it.
      'running' when mailbox.busy => (
          Zn.amber,
          mailbox.isExternal ? 'Disconnecting…' : 'Turning off…'
        ),
      // The record says running, but nothing has answered at that address for
      // a while — trust the socket, not the hub.
      'running' when mailbox.mailboxDownFor != null => (
          Zn.danger,
          "Your mailbox isn't answering · "
              '${formatOutage(mailbox.mailboxDownFor!)}'
        ),
      'running' when mailbox.mailboxUnreachable => (
          Zn.danger,
          "Can't reach your mailbox"
        ),
      'running' => (Zn.ok, 'Running'),
      'provisioning' => (Zn.amber, 'Setting up…'),
      'error' => (Zn.danger, 'Something went wrong'),
      _ => (Zn.muted, 'Off'),
    };

    return Container(
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: Zn.surface,
        borderRadius: BorderRadius.circular(Zn.radius),
        border: Border.all(color: Zn.line),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Container(
                width: 8,
                height: 8,
                decoration: BoxDecoration(color: color, shape: BoxShape.circle),
              ),
              const SizedBox(width: 10),
              Text(headline,
                  style: TextStyle(
                      fontSize: 15, color: color, fontWeight: FontWeight.w700)),
            ],
          ),
          if (r.status != 'none') ...[
            const SizedBox(height: 12),
            if (r.provider != null)
              _kv(
                  'Runs on',
                  mailbox.isFriendHosted
                      ? "A friend's machine"
                      : _providerLabels[r.provider] ?? r.provider!),
            if (r.address != null) _kv('Address', r.address!),
            if (r.status == 'running')
              _kv(
                  'Phone link',
                  mailbox.mailboxUnreachable || mailbox.mailboxDownFor != null
                      ? 'Unreachable'
                      : mailbox.socketConnected
                          ? 'Connected'
                          : 'Reconnecting…'),
            if (r.error != null) _kv('Details', r.error!),
            // Say plainly that nothing happens automatically. The kill switch
            // is the product's promise; a mailbox that restarts itself — or
            // that we restart for you — would quietly break it.
            if (r.status == 'running' && mailbox.mailboxDownFor != null) ...[
              const SizedBox(height: 12),
              Text(
                "You didn't turn this off, so something else stopped it — a "
                'reboot, a crash, or the machine being removed. Nobody '
                'restarts it but you. Messages sent to you meanwhile are '
                'held by your contacts and arrive once it’s back.',
                style: const TextStyle(
                    fontSize: 12.5, color: Zn.muted, height: 1.45),
              ),
            ],
          ],
        ],
      ),
    );
  }

  Widget _kv(String k, String v) => Padding(
        padding: const EdgeInsets.only(top: 4),
        child: Row(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            SizedBox(
                width: 84,
                child: Text(k,
                    style: const TextStyle(color: Zn.muted, fontSize: 12))),
            Expanded(
                child: Text(v, style: Zn.mono(size: 11, color: Zn.text))),
          ],
        ),
      );
}
/// Entry point to the invites screen — hosts (self-host or Machine) can
/// invite friends onto their machine and track who accepted.
class _InvitesEntry extends StatelessWidget {
  final VoidCallback onTap;
  const _InvitesEntry({required this.onTap});

  @override
  Widget build(BuildContext context) {
    return InkWell(
      onTap: onTap,
      borderRadius: BorderRadius.circular(Zn.radius),
      child: Container(
        padding: const EdgeInsets.all(16),
        decoration: BoxDecoration(
          color: Zn.surface,
          borderRadius: BorderRadius.circular(Zn.radius),
          border: Border.all(color: Zn.line),
        ),
        child: Row(
          children: [
            const Icon(Icons.group_add_outlined, color: Zn.orange, size: 20),
            const SizedBox(width: 12),
            const Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text('Invites',
                      style: TextStyle(
                          fontSize: 14,
                          fontWeight: FontWeight.w600,
                          color: Zn.text)),
                  SizedBox(height: 2),
                  Text('Host friends on your machine — send invites and '
                      'see who accepted',
                      style: TextStyle(
                          color: Zn.muted, fontSize: 12, height: 1.35)),
                ],
              ),
            ),
            const Icon(Icons.chevron_right, color: Zn.muted, size: 20),
          ],
        ),
      ),
    );
  }
}

