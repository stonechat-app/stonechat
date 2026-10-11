import 'dart:async';

import 'package:app_links/app_links.dart';
import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import 'core/links.dart';
import 'core/notices.dart';
import 'core/push.dart';
import 'state/app_state.dart';
import 'state/call_state.dart';
import 'state/chat_state.dart';
import 'state/mailbox_state.dart';
import 'ui/add_contact_screen.dart';
import 'ui/backup_screen.dart';
import 'ui/call_screen.dart';
import 'ui/chat_screen.dart';
import 'ui/create_group_screen.dart';
import 'ui/home_screen.dart';
import 'ui/identity_export_screen.dart';
import 'ui/invites_screen.dart';
import 'ui/lock_screen.dart';
import 'ui/mailbox_setup_screen.dart';
import 'ui/my_id_screen.dart';
import 'ui/onboarding_screen.dart';
import 'ui/mailbox_screen.dart';
import 'ui/settings_screen.dart';
import 'ui/theme.dart';

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();

  final app = AppState();
  await app.init();

  final chat = ChatState(app);
  final call = CallState(app, chat);
  // PushService is initialised below; a tap on one of the Android drain's
  // message notifications routes through it, held until the shell listens.
  final push = PushService();
  final notices = LocalNotices();
  await notices.init(onTap: push.openConversation);
  // Surface backgrounded events (e.g. a contact accepting your request) as
  // local notifications.
  chat.onNotice = notices.show;
  final mailbox = MailboxState(
    app,
    onEnvelope: chat.handleIncoming,
    onConnected: () async {
      // Stock the mailbox with prekeys first — peers may be waiting on a
      // bundle to start a session — then flush our own pending outbox.
      try {
        await chat.publishPrekeys();
      } catch (_) {
        // best-effort; retried on the next connect or app resume
      }
      // The device manifest and linked devices' certificates: the primary
      // keeps both current, every device learns the manifest's version.
      await chat.maintainDevices();
      await chat.retryPending();
    },
    onMailbox: chat.setMailbox,
    onProvisioningDone: (ok) {
      // Foregrounded users watch the status flip on screen; the notice is
      // for the "you can leave the app" promise on the setup screen.
      if (WidgetsBinding.instance.lifecycleState == AppLifecycleState.resumed) {
        return;
      }
      notices.show(
        ok ? 'Your mailbox is ready' : 'Mailbox setup failed',
        ok
            ? 'Stonechat is set up — you can send and receive messages.'
            : 'Open Stonechat to see what happened and retry.',
      );
    },
    // Your mailbox stopped answering and you didn't turn it off. We only
    // ever tell you — restarting or rebuilding it is always your call.
    onOutage: (down) => notices.show(
      "Your mailbox isn't answering",
      "It's been unreachable for ${formatOutage(down)}. People can't reach "
          'you until it’s back — open Stonechat to check on it.',
      id: 1,
    ),
  );

  if (app.hasIdentity) {
    await chat.load();
    await mailbox.loadOutage();
  }

  // Optional content-free push wake-ups. No Firebase config → stays disabled,
  // and the app relies on live-socket / on-resume delivery as before.
  await push.init(
    onToken: chat.setPushToken,
    onWake: () {
      if (app.hasIdentity) {
        // onForeground connects straight to the mailbox — refresh() alone
        // would leave us socketless whenever the hub is unreachable.
        mailbox
          ..onForeground()
          ..refresh();
        chat.retryPending();
      }
    },
  );

  runApp(
    MultiProvider(
      providers: [
        ChangeNotifierProvider.value(value: app),
        ChangeNotifierProvider.value(value: chat),
        ChangeNotifierProvider.value(value: call),
        ChangeNotifierProvider.value(value: mailbox),
        Provider<PushService>.value(value: push),
      ],
      child: const StonechatApp(),
    ),
  );

  // Asking the hub about our mailbox is network: never hold the first frame
  // on it. The status strip says "connecting" meanwhile, and says so plainly
  // if the hub doesn't answer.
  if (app.hasIdentity) unawaited(mailbox.refresh());
}

class StonechatApp extends StatefulWidget {
  const StonechatApp({super.key});

  @override
  State<StonechatApp> createState() => _StonechatAppState();
}

class _StonechatAppState extends State<StonechatApp>
    with WidgetsBindingObserver {
  final _navKey = GlobalKey<NavigatorState>();
  final _appLinks = AppLinks();
  StreamSubscription<Uri>? _linkSub;
  CallState? _call;
  bool _callRouteUp = false;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
    _call = context.read<CallState>();
    _call!.addListener(_syncCallRoute);
    // A tapped notification opens the conversation it was about.
    context.read<PushService>().onOpen = _openConversation;
    // Contact invite universal links (https://stonechat.app/add#SC-…).
    _linkSub = _appLinks.uriLinkStream.listen(_handleInviteLink);
    _appLinks.getInitialLink().then((uri) {
      if (uri != null) {
        WidgetsBinding.instance.addPostFrameCallback(
          (_) => _handleInviteLink(uri),
        );
      }
    });
  }

  @override
  void dispose() {
    context.read<PushService>().onOpen = null;
    _linkSub?.cancel();
    _call?.removeListener(_syncCallRoute);
    WidgetsBinding.instance.removeObserver(this);
    super.dispose();
  }

  /// A tapped invite link opens add-contact with the invite prefilled; the
  /// user still confirms before a request is sent. Ignored until the user has
  /// their own identity (there's nothing to add a contact to yet). The raw
  /// fragment goes through as typed so a hub-tagged invite keeps its tag.
  void _handleInviteLink(Uri uri) {
    if (stonechatInviteFromUri(uri) == null || !mounted) return;
    if (!context.read<AppState>().hasIdentity) return;
    _navKey.currentState?.push(
      MaterialPageRoute<void>(
        builder: (_) => AddContactScreen(initialId: uri.fragment),
      ),
    );
  }

  /// The conversation a tapped notification named. Replaces whatever chat
  /// is open rather than stacking on it: the user asked for this one. Unknown
  /// ids (a contact removed since the push was shown) just leave the list up.
  void _openConversation(String conversationId) {
    if (!mounted || !context.read<AppState>().hasIdentity) return;
    final chat = context.read<ChatState>();
    final group = chat.groupById(conversationId);
    final contact = group == null ? chat.contactById(conversationId) : null;
    if (group == null && contact == null) return;
    _navKey.currentState
      ?..popUntil((route) => route.isFirst)
      ..push(
        MaterialPageRoute<void>(
          builder: (_) => group != null
              ? ChatScreen.group(group: group)
              : ChatScreen(contact: contact!),
        ),
      );
  }

  /// The call surface follows CallState: pushed over whatever the user is
  /// doing when a call starts (either direction), popped when it ends.
  void _syncCallRoute() {
    final call = _call;
    if (call == null) return;
    if (call.inCall && !_callRouteUp) {
      _callRouteUp = true;
      _navKey.currentState?.push(
        MaterialPageRoute<void>(
          fullscreenDialog: true,
          builder: (_) => const CallScreen(),
        ),
      );
    } else if (!call.inCall && _callRouteUp) {
      _callRouteUp = false;
      _navKey.currentState?.pop();
      // A call kept the mailbox socket open past `paused` (signaling rides
      // it); if the call ends while we're still backgrounded, close it now
      // so queued envelopes go through the push gateway.
      if (WidgetsBinding.instance.lifecycleState != AppLifecycleState.resumed) {
        context.read<MailboxState>().onBackground();
      }
    }
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    final app = context.read<AppState>();
    if (!app.hasIdentity) return;
    if (state == AppLifecycleState.resumed) {
      final chat = context.read<ChatState>();
      final mailbox = context.read<MailboxState>();
      // Reconcile with what the notification extension wrote BEFORE the
      // socket reconnects — new envelopes must never meet a stale session
      // cache (chat_state.reloadAfterExtension).
      unawaited(
        chat.reloadAfterExtension().then((_) {
          mailbox
            ..onForeground()
            ..refresh();
          chat.retryPending();
        }),
      );
    } else if (state == AppLifecycleState.paused) {
      // Mid-call the app keeps running in the background and signaling
      // (ICE, hangup) rides this socket — those envelopes are transient,
      // never queued, so a closed socket would drop them.
      if (!(_call?.inCall ?? false)) {
        context.read<MailboxState>().onBackground();
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    final app = context.watch<AppState>();
    return MaterialApp(
      title: 'Stonechat',
      debugShowCheckedModeBanner: false,
      navigatorKey: _navKey,
      theme: stonechatTheme(),
      // The lock gate sits above the Navigator so it covers every route.
      builder: (context, child) => LockGate(child: child ?? const SizedBox()),
      initialRoute: app.hasIdentity ? '/home' : '/onboarding',
      routes: {
        '/onboarding': (_) => const OnboardingScreen(),
        '/mailbox-setup': (_) => const MailboxSetupScreen(),
        '/home': (_) => const HomeScreen(),
        '/add-contact': (_) => const AddContactScreen(),
        '/create-group': (_) => const CreateGroupScreen(),
        '/my-id': (_) => const MyIdScreen(),
        '/mailbox': (_) => const MailboxScreen(),
        '/invites': (_) => const InvitesScreen(),
        '/settings': (_) => const SettingsScreen(),
        '/backup': (_) => const BackupScreen(),
        '/identity-export': (_) => const IdentityExportScreen(),
      },
    );
  }
}
