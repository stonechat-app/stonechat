/// Host-owner's invites: mint invites for friends and see who accepted.
///
/// Talks straight to the user's own mailbox host (PROTOCOL.md "Mailbox host") —
/// the hub is never involved. The mailbox host address + admin token are asked for
/// once and kept in the keystore.
library;

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:provider/provider.dart';

import '../core/api.dart';
import '../state/app_state.dart';
import '../state/chat_state.dart';
import '../state/mailbox_state.dart';
import 'theme.dart';
import 'widgets.dart';

class InvitesScreen extends StatefulWidget {
  const InvitesScreen({super.key});

  @override
  State<InvitesScreen> createState() => _InvitesScreenState();
}

class _InvitesScreenState extends State<InvitesScreen> {
  final _address = TextEditingController(text: 'https://');
  final _adminToken = TextEditingController();
  bool _busy = false;
  bool _autoSetup = false; // creds came from the hub (pre-installed agent)
  List<HostInviteStatus>? _invites;

  @override
  void initState() {
    super.initState();
    final app = context.read<AppState>();
    if (app.mailboxHostAddress != null) {
      _address.text = app.mailboxHostAddress!;
      _refresh();
    } else {
      // Machine-plan VMs come with the mailbox host pre-installed — the hub gave
      // us its address + admin token, so connect without asking anything.
      final record = context.read<MailboxState>().record;
      if (record.mailboxHostAddress != null &&
          record.mailboxHostAdminToken != null) {
        _address.text = record.mailboxHostAddress!;
        _adminToken.text = record.mailboxHostAdminToken!;
        _autoSetup = true;
        WidgetsBinding.instance
            .addPostFrameCallback((_) => _connect(auto: true));
      }
    }
  }

  bool get _connected => context.read<AppState>().mailboxHostAddress != null;

  Future<void> _connect({bool auto = false}) async {
    final url = _address.text.trim().replaceAll(RegExp(r'/+$'), '');
    final token = _adminToken.text.trim();
    if (url.isEmpty || url == 'https:' || token.isEmpty) {
      showZnSnack(context, 'Enter your mailbox host address and admin token',
          error: true);
      return;
    }
    setState(() => _busy = true);
    final app = context.read<AppState>();
    try {
      final fp = await observeCertFingerprint(url);
      if (fp == null) {
        throw ApiException(auto
            ? "Your mailbox VM isn't answering on the mailbox host port yet — "
                "it can take a few minutes after setup. Pull down to retry."
            : "Couldn't reach a Stonechat mailbox host at that address");
      }
      // listing doubles as the admin-token check
      final invites = await listHostInvites(url, fp, token);
      await app.setMailboxHost(url, token, fp);
      _adminToken.clear();
      if (mounted) setState(() => _invites = invites);
    } catch (e) {
      if (mounted) showZnSnack(context, '$e', error: true);
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<void> _refresh() async {
    final app = context.read<AppState>();
    if (app.mailboxHostAddress == null) return;
    try {
      final invites = await listHostInvites(app.mailboxHostAddress!,
          app.mailboxHostTlsFp!, app.mailboxHostAdminToken!);
      if (mounted) setState(() => _invites = invites);
    } catch (e) {
      if (mounted) showZnSnack(context, '$e', error: true);
    }
  }

  Future<void> _createInvite() async {
    final app = context.read<AppState>();
    setState(() => _busy = true);
    try {
      final invite = await createHostInvite(app.mailboxHostAddress!,
          app.mailboxHostTlsFp!, app.mailboxHostAdminToken!);
      await Clipboard.setData(ClipboardData(text: invite));
      if (mounted) {
        showZnSnack(context, 'Invite created and copied — send it to a friend');
      }
      await _refresh();
    } catch (e) {
      if (mounted) showZnSnack(context, '$e', error: true);
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<void> _forgetAgent() async {
    await context.read<AppState>().setMailboxHost(null, null, null);
    setState(() {
      _invites = null;
      _address.text = 'https://';
      _adminToken.clear();
    });
  }

  @override
  Widget build(BuildContext context) {
    context.watch<AppState>(); // rebuild when mailbox host creds change
    return Scaffold(
      appBar: AppBar(
        title: const Text('Invites',
            style: TextStyle(fontSize: 17, fontWeight: FontWeight.w600)),
      ),
      body: _connected ? _invitesView() : _setupView(),
    );
  }

  // -- first run: point the app at your own mailbox host ----------------------

  Widget _setupView() {
    // Machine-plan VM: the mailbox host is already on the box and the hub gave us
    // its credentials — no form, just a connect (with retry while the VM is
    // still finishing its first boot).
    if (_autoSetup) {
      return ListView(
        padding: const EdgeInsets.all(20),
        children: [
          const Text(
            'Host friends on your machine',
            style: TextStyle(
                color: Zn.text, fontSize: 16, fontWeight: FontWeight.w700),
          ),
          const SizedBox(height: 8),
          const Text(
            'Your mailbox VM comes with the Stonechat mailbox host built in. Each '
            'friend who accepts an invite gets their own mailbox on your box '
            '— you can see that they host with you, never their messages.',
            style: TextStyle(color: Zn.muted, fontSize: 13, height: 1.45),
          ),
          const SizedBox(height: 20),
          SizedBox(
            width: double.infinity,
            height: 48,
            child: FilledButton(
              onPressed: _busy ? null : () => _connect(auto: true),
              child: _busy
                  ? const SizedBox(
                      width: 18,
                      height: 18,
                      child: CircularProgressIndicator(strokeWidth: 2))
                  : const Text('Connect to your machine'),
            ),
          ),
        ],
      );
    }
    return ListView(
      padding: const EdgeInsets.all(20),
      children: [
        const Text(
          'Host friends on your machine',
          style: TextStyle(
              color: Zn.text, fontSize: 16, fontWeight: FontWeight.w700),
        ),
        const SizedBox(height: 8),
        const Text(
          'Run the Stonechat mailbox host on your own server, then connect '
          'it here to create invites. Each friend who accepts gets their own '
          'mailbox on your box — you can see that they host with you, never '
          'their messages.',
          style: TextStyle(color: Zn.muted, fontSize: 13, height: 1.45),
        ),
        const SizedBox(height: 20),
        _field('Mailbox host address', _address),
        const SizedBox(height: 12),
        _field('Admin token', _adminToken),
        const SizedBox(height: 16),
        SizedBox(
          width: double.infinity,
          height: 48,
          child: FilledButton(
            onPressed: _busy ? null : _connect,
            child: _busy
                ? const SizedBox(
                    width: 18,
                    height: 18,
                    child: CircularProgressIndicator(strokeWidth: 2))
                : const Text('Connect'),
          ),
        ),
      ],
    );
  }

  // -- connected: mint + track ----------------------------------------------

  Widget _invitesView() {
    final app = context.read<AppState>();
    final invites = _invites;
    return RefreshIndicator(
      color: Zn.orange,
      onRefresh: _refresh,
      child: ListView(
        physics: const AlwaysScrollableScrollPhysics(),
        padding: const EdgeInsets.all(20),
        children: [
          Row(
            children: [
              Expanded(
                child: Text(
                  app.mailboxHostAddress!,
                  style: Zn.mono(size: 11),
                  overflow: TextOverflow.ellipsis,
                ),
              ),
              TextButton(
                onPressed: _forgetAgent,
                child: const Text('Change',
                    style: TextStyle(color: Zn.muted, fontSize: 12)),
              ),
            ],
          ),
          const SizedBox(height: 4),
          SizedBox(
            width: double.infinity,
            height: 48,
            child: FilledButton.icon(
              onPressed: _busy ? null : _createInvite,
              icon: const Icon(Icons.add, size: 18),
              label: const Text('New invite'),
            ),
          ),
          const SizedBox(height: 6),
          const Text(
            'An invite is a one-time code, valid for 3 days. Send it to a '
            'friend any way you like — it\'s copied when you create it.',
            style: TextStyle(color: Zn.muted, fontSize: 12, height: 1.4),
          ),
          const SizedBox(height: 20),
          if (invites == null)
            const Center(
                child: Padding(
              padding: EdgeInsets.all(24),
              child: CircularProgressIndicator(
                  strokeWidth: 2, color: Zn.orange),
            ))
          else if (invites.isEmpty)
            const Padding(
              padding: EdgeInsets.symmetric(vertical: 24),
              child: Text(
                'No invites yet. Create one and send it to a friend — '
                'you\'ll see here when they accept.',
                textAlign: TextAlign.center,
                style: TextStyle(color: Zn.muted, fontSize: 13, height: 1.45),
              ),
            )
          else ...[
            Text('SENT INVITES', style: Zn.mono(size: 10, letterSpacing: 2)),
            const SizedBox(height: 10),
            for (final invite in invites) ...[
              _InviteCard(invite: invite),
              const SizedBox(height: 10),
            ],
          ],
        ],
      ),
    );
  }

  Widget _field(String label, TextEditingController controller) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(label, style: const TextStyle(color: Zn.muted, fontSize: 12)),
        const SizedBox(height: 6),
        TextField(
            controller: controller, style: Zn.mono(size: 13, color: Zn.text)),
      ],
    );
  }
}

class _InviteCard extends StatelessWidget {
  final HostInviteStatus invite;
  const _InviteCard({required this.invite});

  @override
  Widget build(BuildContext context) {
    final accepted = invite.redeemedBy.isNotEmpty;
    final open = invite.usesLeft > 0 && !invite.expired;
    final (color, label) = accepted
        ? (Zn.ok, invite.uses > 1 ? 'Accepted · ${invite.redeemedBy.length}/${invite.uses}' : 'Accepted')
        : invite.expired
            ? (Zn.muted, 'Expired')
            : (Zn.amber, 'Waiting');

    return Container(
      padding: const EdgeInsets.all(14),
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
                decoration:
                    BoxDecoration(color: color, shape: BoxShape.circle),
              ),
              const SizedBox(width: 8),
              Text(label,
                  style: TextStyle(
                      color: color,
                      fontSize: 13,
                      fontWeight: FontWeight.w700)),
              const Spacer(),
              Text(_when(invite.createdAt), style: Zn.mono(size: 10)),
            ],
          ),
          if (accepted) ...[
            const SizedBox(height: 8),
            for (final id in invite.redeemedBy)
              Padding(
                padding: const EdgeInsets.only(top: 2),
                child: Text(_guestName(context, id),
                    style: const TextStyle(color: Zn.text, fontSize: 13)),
              ),
          ],
          if (open) ...[
            const SizedBox(height: 8),
            Row(
              children: [
                Expanded(
                  child: Text(_expiry(invite.expiresAt),
                      style: const TextStyle(color: Zn.muted, fontSize: 12)),
                ),
                TextButton.icon(
                  style: TextButton.styleFrom(
                      padding: EdgeInsets.zero,
                      minimumSize: const Size(0, 32)),
                  onPressed: () async {
                    await Clipboard.setData(
                        ClipboardData(text: invite.invite));
                    if (context.mounted) showZnSnack(context, 'Invite copied');
                  },
                  icon: const Icon(Icons.copy, size: 14),
                  label: const Text('Copy', style: TextStyle(fontSize: 12)),
                ),
              ],
            ),
          ],
        ],
      ),
    );
  }

  /// A redeemer we already chat with shows as their name; anyone else as a
  /// shortened Stonechat ID.
  String _guestName(BuildContext context, String stonechatId) {
    final contacts = context.read<ChatState>().contacts;
    for (final c in contacts) {
      if (c.stonechatId == stonechatId) return c.displayName;
    }
    return stonechatId.length > 16 ? '${stonechatId.substring(0, 15)}…' : stonechatId;
  }

  String _when(DateTime t) {
    final d = DateTime.now().difference(t);
    if (d.inDays >= 1) return '${d.inDays}d ago';
    if (d.inHours >= 1) return '${d.inHours}h ago';
    return 'just now';
  }

  String _expiry(DateTime t) {
    final d = t.difference(DateTime.now());
    if (d.inDays >= 2) return 'Expires in ${d.inDays} days';
    if (d.inHours >= 1) return 'Expires in ${d.inHours} h';
    return 'Expires soon';
  }
}
