import Flutter
import UIKit

/// Shared with the notification service extension (NotificationService/):
/// the SQLCipher DB lives in this container, the keychain items carry it
/// as their access group.
let appGroupId = "group.app.stonechat.mobile"

@main
@objc class AppDelegate: FlutterAppDelegate, FlutterImplicitEngineDelegate {
  override func application(
    _ application: UIApplication,
    didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?
  ) -> Bool {
    return super.application(application, didFinishLaunchingWithOptions: launchOptions)
  }

  func didInitializeImplicitFlutterEngine(_ engineBridge: FlutterImplicitEngineBridge) {
    GeneratedPluginRegistrant.register(with: engineBridge.pluginRegistry)
    guard let registrar = engineBridge.pluginRegistry.registrar(forPlugin: "StonechatNative")
    else { return }
    let channel = FlutterMethodChannel(
      name: "stonechat/native", binaryMessenger: registrar.messenger())
    channel.setMethodCallHandler { call, result in
      switch call.method {
      case "appGroupPath":
        // Where the database belongs so the notification extension can
        // open it too. nil (no entitlement / simulator oddity) makes the
        // Dart side fall back to the app container.
        let url = FileManager.default.containerURL(
          forSecurityApplicationGroupIdentifier: appGroupId)
        result(url?.path)
      default:
        result(FlutterMethodNotImplemented)
      }
    }
  }
}
