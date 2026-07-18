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
import 'state/server_state.dart';
import 'ui/add_contact_screen.dart';
import 'ui/call_screen.dart';
import 'ui/create_group_screen.dart';
import 'ui/home_screen.dart';
import 'ui/invites_screen.dart';
import 'ui/lock_screen.dart';
import 'ui/mailbox_setup_screen.dart';
import 'ui/my_id_screen.dart';
import 'ui/onboarding_screen.dart';
import 'ui/server_screen.dart';
import 'ui/settings_screen.dart';
import 'ui/theme.dart';

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();

  final app = AppState();
  await app.init();

  final chat = ChatState(app);
  final call = CallState(app, chat);
  final notices = LocalNotices();
  await notices.init();
  // Surface backgrounded events (e.g. a contact accepting your request) as
  // local notifications.
  chat.onNotice = notices.show;
  final server = ServerState(
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
      await chat.retryPending();
    },
    onMailbox: chat.setMailbox,
    onProvisioningDone: (ok) {
      // Foregrounded users watch the status flip on screen; the notice is
      // for the "you can leave the app" promise on the setup screen.
      if (WidgetsBinding.instance.lifecycleState ==
          AppLifecycleState.resumed) {
        return;
      }
      notices.show(
        ok ? 'Your mailbox is ready' : 'Mailbox setup failed',
        ok
            ? 'Zeon is set up — you can send and receive messages.'
            : 'Open Zeon to see what happened and retry.',
      );
    },
  );

  if (app.hasIdentity) {
    await chat.load();
    await server.refresh();
  }

  // Optional content-free push wake-ups. No Firebase config → stays disabled,
  // and the app relies on live-socket / on-resume delivery as before.
  final push = PushService();
  await push.init(
    onToken: chat.setPushToken,
    onWake: () {
      if (app.hasIdentity) {
        // onForeground connects straight to the mailbox — refresh() alone
        // would leave us socketless whenever the hub is unreachable.
        server
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
        ChangeNotifierProvider.value(value: server),
        Provider<PushService>.value(value: push),
      ],
      child: const ZeonApp(),
    ),
  );
}

class ZeonApp extends StatefulWidget {
  const ZeonApp({super.key});

  @override
  State<ZeonApp> createState() => _ZeonAppState();
}

class _ZeonAppState extends State<ZeonApp> with WidgetsBindingObserver {
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
    // Contact invite universal links (https://zeonchat.com/add#ZC-…).
    _linkSub = _appLinks.uriLinkStream.listen(_handleInviteLink);
    _appLinks.getInitialLink().then((uri) {
      if (uri != null) {
        WidgetsBinding.instance
            .addPostFrameCallback((_) => _handleInviteLink(uri));
      }
    });
  }

  @override
  void dispose() {
    _linkSub?.cancel();
    _call?.removeListener(_syncCallRoute);
    WidgetsBinding.instance.removeObserver(this);
    super.dispose();
  }

  /// A tapped invite link opens add-contact with the ID prefilled; the user
  /// still confirms before a request is sent. Ignored until the user has their
  /// own identity (there's nothing to add a contact to yet).
  void _handleInviteLink(Uri uri) {
    final id = zeonIdFromUri(uri);
    if (id == null || !mounted) return;
    if (!context.read<AppState>().hasIdentity) return;
    _navKey.currentState?.push(MaterialPageRoute<void>(
      builder: (_) => AddContactScreen(initialId: id),
    ));
  }

  /// The call surface follows CallState: pushed over whatever the user is
  /// doing when a call starts (either direction), popped when it ends.
  void _syncCallRoute() {
    final call = _call;
    if (call == null) return;
    if (call.inCall && !_callRouteUp) {
      _callRouteUp = true;
      _navKey.currentState?.push(MaterialPageRoute<void>(
        fullscreenDialog: true,
        builder: (_) => const CallScreen(),
      ));
    } else if (!call.inCall && _callRouteUp) {
      _callRouteUp = false;
      _navKey.currentState?.pop();
      // A call kept the mailbox socket open past `paused` (signaling rides
      // it); if the call ends while we're still backgrounded, close it now
      // so queued envelopes go through the push gateway.
      if (WidgetsBinding.instance.lifecycleState !=
          AppLifecycleState.resumed) {
        context.read<ServerState>().onBackground();
      }
    }
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    final app = context.read<AppState>();
    if (!app.hasIdentity) return;
    if (state == AppLifecycleState.resumed) {
      context.read<ServerState>()
        ..onForeground()
        ..refresh();
      context.read<ChatState>().retryPending();
    } else if (state == AppLifecycleState.paused) {
      // Mid-call the app keeps running in the background and signaling
      // (ICE, hangup) rides this socket — those envelopes are transient,
      // never queued, so a closed socket would drop them.
      if (!(_call?.inCall ?? false)) {
        context.read<ServerState>().onBackground();
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    final app = context.watch<AppState>();
    return MaterialApp(
      title: 'Zeon',
      debugShowCheckedModeBanner: false,
      navigatorKey: _navKey,
      theme: zeonTheme(),
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
        '/server': (_) => const ServerScreen(),
        '/invites': (_) => const InvitesScreen(),
        '/settings': (_) => const SettingsScreen(),
      },
    );
  }
}
