import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import 'state/app_state.dart';
import 'state/chat_state.dart';
import 'state/server_state.dart';
import 'ui/add_contact_screen.dart';
import 'ui/create_group_screen.dart';
import 'ui/home_screen.dart';
import 'ui/mailbox_setup_screen.dart';
import 'ui/my_id_screen.dart';
import 'ui/onboarding_screen.dart';
import 'ui/server_screen.dart';
import 'ui/theme.dart';

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();

  final app = AppState();
  await app.init();

  final chat = ChatState(app);
  final server = ServerState(
    app,
    onEnvelope: chat.handleIncoming,
    onConnected: chat.retryPending,
    onMailbox: chat.setMailbox,
  );

  if (app.hasIdentity) {
    await chat.load();
    await server.refresh();
  }

  runApp(
    MultiProvider(
      providers: [
        ChangeNotifierProvider.value(value: app),
        ChangeNotifierProvider.value(value: chat),
        ChangeNotifierProvider.value(value: server),
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
  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
  }

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    super.dispose();
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    if (state == AppLifecycleState.resumed) {
      final app = context.read<AppState>();
      if (app.hasIdentity) {
        context.read<ServerState>().refresh();
        context.read<ChatState>().retryPending();
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    final app = context.watch<AppState>();
    return MaterialApp(
      title: 'Zeon',
      debugShowCheckedModeBanner: false,
      theme: zeonTheme(),
      initialRoute: app.hasIdentity ? '/home' : '/onboarding',
      routes: {
        '/onboarding': (_) => const OnboardingScreen(),
        '/mailbox-setup': (_) => const MailboxSetupScreen(),
        '/home': (_) => const HomeScreen(),
        '/add-contact': (_) => const AddContactScreen(),
        '/create-group': (_) => const CreateGroupScreen(),
        '/my-id': (_) => const MyIdScreen(),
        '/server': (_) => const ServerScreen(),
      },
    );
  }
}
