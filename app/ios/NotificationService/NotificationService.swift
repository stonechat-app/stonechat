// Stonechat notification service extension: the push is content-free
// ("You have new messages" — push_gateway/main.py), so this process drains the
// user's own mailbox, decrypts what it safely can with the SAME compiled
// protocol core the app uses (stonechat-core), stores the messages, and
// rewrites the notification to "Maria: see you at 8".
//
// Scope, deliberately narrow:
// - Stores and acks only DM text (`msg`) from accepted, unblocked senders
//   with an existing session on the sending device. Write-then-ack: message
//   row + advanced session state commit in one transaction BEFORE the ack
//   frame. Dying mid-work never loses mail — the envelope redelivers, the
//   app dedupes by id (INSERT OR IGNORE).
// - Group text and media (`group_msg`, `media`, `group_media`) are opened
//   for the preview only: decrypted from the stored state, which is then
//   discarded, and left UNACKED for the app. The ratchet is state-in /
//   state-out, so the app decrypts the same envelope from the same state
//   later; what it does with it (transcript hash, roster bookkeeping, the
//   blob fetch) is not reimplemented here.
// - Everything else (handshake first-messages, receipts, group control
//   traffic) is left untouched for the app; the ratchet's skipped-key
//   stash absorbs the ordering gap.
// - What the alert shows is the user's choice (Settings › Notifications,
//   kv "notification_preview"): sender and message, sender only, or the
//   generic text — in which case this still drains DM text so the app
//   opens up to date.
// - Every failure path falls back to the generic alert.

import UserNotifications

class NotificationService: UNNotificationServiceExtension {
  private var contentHandler: ((UNNotificationContent) -> Void)?
  private var bestAttempt: UNMutableNotificationContent?
  private let work = DispatchQueue(label: "stonechat.nse.drain", qos: .userInitiated)

  override func didReceive(
    _ request: UNNotificationRequest,
    withContentHandler contentHandler: @escaping (UNNotificationContent) -> Void
  ) {
    self.contentHandler = contentHandler
    bestAttempt = (request.content.mutableCopy() as? UNMutableNotificationContent)
    work.async { [weak self] in
      guard let self else { return }
      let shown = Drainer().run(deadline: Date().addingTimeInterval(20))
      self.finish(with: shown)
    }
  }

  override func serviceExtensionTimeWillExpire() {
    // Out of time: show what we have (the generic alert if the drain
    // didn't get anywhere). Anything not yet acked stays queued.
    finish(with: nil)
  }

  private func finish(with summary: DrainSummary?) {
    guard let handler = contentHandler, let content = bestAttempt else { return }
    contentHandler = nil
    if let summary, summary.shown.isEmpty, summary.silenced > 0 {
      // Everything drained was for a muted conversation. An extension
      // cannot cancel the alert, but content with no title, body or sound
      // is not presented — mute, honoured where the notification is made.
      content.title = ""
      content.body = ""
      content.sound = nil
      content.badge = nil
    } else if let summary, let (title, body, thread) = summary.notification() {
      content.title = title
      content.body = body
      content.threadIdentifier = thread
      // A tap on this banner should land in the conversation, not the
      // list: the app reads this back out of the tapped notification
      // (core/push.dart). Several conversations → no single place to go.
      if thread != DrainSummary.mixedThread {
        var info = content.userInfo
        info["conversation"] = thread
        content.userInfo = info
      }
    }
    handler(content)
  }
}

// MARK: - drain outcome → notification copy

struct ShownMessage {
  let conversationId: String
  let title: String  // sender, or "Group · Sender"
  let body: String
}

/// How much of a message the alert may show. Written by the app
/// (settings_screen.dart) into kv "notification_preview"; absent → full.
enum PreviewMode: String {
  case full  // "Maria: see you at 8"
  case sender  // "Maria: New message"
  case none  // the generic alert, untouched
}

struct DrainSummary {
  var shown: [ShownMessage] = []
  /// Drained, but for a muted conversation: nothing to show.
  var silenced = 0
  var mode: PreviewMode = .full

  /// Thread for a batch spanning conversations: grouped together, opens the list.
  static let mixedThread = "stonechat-mixed"

  func notification() -> (title: String, body: String, thread: String)? {
    guard mode != .none, let last = shown.last else { return nil }
    if shown.count == 1 {
      return (last.title, mode == .full ? last.body : "New message", last.conversationId)
    }
    let conversations = Set(shown.map(\.conversationId))
    if conversations.count == 1 {
      return (last.title, "\(shown.count) new messages", last.conversationId)
    }
    return ("Stonechat", "\(shown.count) new messages", Self.mixedThread)
  }
}

// MARK: - the drain

final class Drainer {
  private var db: Database?
  private var ownId = ""
  private var ownDevice = 1
  private var sealSeed = Data()
  private var silenced = 0
  private var mode = PreviewMode.full

  func run(deadline: Date) -> DrainSummary? {
    // Identity, device keys and DB key from the shared keychain
    // (first_unlock: readable here as long as the phone has been unlocked
    // once since boot). The device keys are what envelopes are sealed to;
    // the identity secret is not needed here, so a linked device drains too.
    guard
      let dbKey = Keychain.read("sc_db_key"),
      let ownId = Keychain.read("sc_id"),
      let deviceKeysJson = Keychain.read("sc_device_keys"),
      let deviceKeys = try? JSONSerialization.jsonObject(
        with: Data(deviceKeysJson.utf8)) as? [String: Any],
      let sealB64 = deviceKeys["seal"] as? String,
      let sealSeed = Data(base64Encoded: sealB64), sealSeed.count == 32
    else {
      nseLog.error("no identity or device keys in the shared keychain — nothing to drain")
      return nil
    }
    guard let db = Database(key: dbKey) else {
      nseLog.error("shared database did not open (missing file or wrong key)")
      return nil
    }
    self.db = db
    self.ownId = ownId
    self.sealSeed = sealSeed

    // Own mailbox coordinates, mirrored into kv by ChatState.setMailbox.
    guard
      let mailboxJson = db.kvGetString("own_mailbox"),
      let mailbox = try? JSONSerialization.jsonObject(
        with: Data(mailboxJson.utf8)) as? [String: Any],
      let address = mailbox["address"] as? String,
      let token = mailbox["token"] as? String,
      let tlsFp = mailbox["tls_fp"] as? String
    else {
      nseLog.error("no mailbox coordinates in kv — open the app once to store them")
      return nil
    }
    // Which of our devices this is: envelopes are addressed per device and
    // the device number is bound into every message's associated data.
    ownDevice = mailbox["device_id"] as? Int ?? 1
    mode = PreviewMode(rawValue: db.kvGetString("notification_preview") ?? "") ?? .full

    let socket = PinnedWebSocket(address: address, token: token, tlsFp: tlsFp)
    guard socket.connect(timeout: 8) else {
      nseLog.error("could not build the mailbox URL")
      return nil
    }
    defer { socket.close() }

    var summary = DrainSummary()
    var frames = 0
    // The relay pushes the whole queue on attach and sends no end marker,
    // so an idle window means drained. The first frame doubles as proof
    // the pinned connection stood up — hence the longer window for it
    // (TLS handshake + queue read) and a short one after.
    var window: TimeInterval = 8
    while Date() < deadline {
      switch socket.receive(timeout: window) {
      case .text(let frame):
        frames += 1
        window = 1.5
        if let shown = process(frame: frame, socket: socket) {
          summary.shown.append(shown)
        }
      case .idle:
        nseLog.info("mailbox idle after \(frames) frame(s) — drained")
        return done(summary)
      case .failed(let reason):
        nseLog.error("mailbox socket failed: \(reason, privacy: .public)")
        return done(summary)
      }
    }
    nseLog.info("deadline reached after \(frames) frame(s), \(summary.shown.count) shown")
    return done(summary)
  }

  private func done(_ summary: DrainSummary) -> DrainSummary? {
    var s = summary
    s.silenced = silenced
    s.mode = mode
    return s.shown.isEmpty && s.silenced == 0 ? nil : s
  }

  /// What a media message reads as: a label for its kind, never the file.
  /// Same words as the Android drain (core/push_drain.dart).
  private static func mediaLabel(_ payload: [String: Any]) -> String {
    switch payload["kind"] as? String {
    case "image": return "📷 Photo"
    case "sticker": return "Sticker"
    case "audio": return "🎤 Voice message"
    case "video": return "🎥 Video"
    case "file": return "📎 \((payload["name"] as? String).map { ($0 as NSString).lastPathComponent } ?? "File")"
    default: return "New message"
    }
  }

  /// One sealed envelope. Returns a displayable line when the message was
  /// opened (DM text: stored + acked; anything else: previewed and left
  /// for the app); nil when it was skipped.
  private func process(frame: String, socket: PinnedWebSocket) -> ShownMessage? {
    guard let db,
      let sealed = try? JSONSerialization.jsonObject(with: Data(frame.utf8))
        as? [String: Any],
      let envelopeId = sealed["id"] as? String,
      let sealedB64 = sealed["sealed"] as? String,
      let sealedBytes = Data(base64Encoded: sealedB64),
      let innerData = Core.unseal(sealSeed: sealSeed, sealed: sealedBytes),
      let inner = try? JSONSerialization.jsonObject(with: innerData) as? [String: Any],
      let type = inner["type"] as? String,
      let from = inner["from"] as? String,
      let fromDevice = inner["from_device"] as? Int,
      let to = inner["to"] as? String, to == ownId,
      let device = inner["device"] as? Int, device == ownDevice,
      let id = inner["id"] as? String, id == envelopeId
    else {
      nseLog.info("envelope did not unseal to this device — left for the app")
      return nil
    }

    // Text and media only; DM text is the one kind this process keeps.
    let stores = type == "msg"
    let isGroup = type == "group_msg" || type == "group_media"
    let isMedia = type == "media" || type == "group_media"
    guard stores || isGroup || isMedia else {
      nseLog.info("type \(type, privacy: .public) is app-only — left unacked")
      return nil
    }
    // A handshake first-message establishes or replaces a session; which
    // one survives a race is the app's call (core/handshake.dart).
    guard inner["x3dh"] == nil else {
      nseLog.info("handshake envelope — left for the app")
      return nil
    }
    guard
      let header = inner["ratchet"] as? [String: Any],
      let nonceB64 = inner["nonce"] as? String,
      let nonce = Data(base64Encoded: nonceB64),
      let ctB64 = inner["ciphertext"] as? String,
      let ciphertext = Data(base64Encoded: ctB64)
    else { return nil }

    // Sender must be an accepted, unblocked contact with a session —
    // checked BEFORE any ratchet state is touched. Blocks live in their own
    // table (anyone can be blocked, not only contacts); a blocked sender's
    // envelope is left for the app, which drops or collapses it.
    guard
      let contact = db.query(
        "SELECT display_name, status FROM contacts WHERE stonechat_id = ?",
        [from]),
      contact[1] == "accepted",
      // `query` answers nil for "no row" and for "no such table" alike, so
      // require the table first: after an update, before the app has run
      // once and created it, fail safe to the generic alert.
      db.query("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
               ["blocked"]) != nil,
      db.query("SELECT 1 FROM blocked WHERE stonechat_id = ?", [from]) == nil,
      // Sessions are per sending device (PROTOCOL.md "Devices"); holding
      // one means the app accepted that device off the sender's manifest.
      let stateJson = db.query(
        "SELECT state FROM sessions WHERE peer_id = ? AND device_id = ?",
        [from, String(fromDevice)])?.first ?? nil
    else {
      nseLog.info("no accepted contact or no established session — left for the app")
      return nil
    }
    let senderName = contact[0] ?? from

    // Both device numbers are bound, exactly as every sender binds them
    // (chat_state.dart _openEnvelope); any other string decrypts nothing.
    guard
      let headerData = try? JSONSerialization.data(withJSONObject: header),
      let result = Core.sessionDecrypt(
        stateJson: Data(stateJson.utf8),
        headerJson: headerData,
        nonce: nonce,
        ciphertext: ciphertext,
        ad: "stonechat/v1|\(from)|\(fromDevice)|\(to)|\(device)|\(type)"),
      let payload = try? JSONSerialization.jsonObject(with: result.plaintext)
        as? [String: Any]
    else {
      // Refusal is normal (out-of-order, app got there first): the stored
      // state is untouched and the app will retry.
      nseLog.info("ratchet decrypt refused — state untouched, left for the app")
      return nil
    }
    let text: String
    if isMedia {
      text = Self.mediaLabel(payload)
    } else {
      guard let t = payload["text"] as? String else { return nil }
      text = t
    }

    // Group context (name + membership), resolved before committing.
    var conversationId = from
    var senderId: String? = nil
    var title = senderName
    if isGroup {
      guard
        let groupId = payload["group_id"] as? String,
        let group = db.query("SELECT name FROM groups WHERE id = ?", [groupId]),
        let member = db.query(
          "SELECT display_name FROM group_members WHERE group_id = ? AND stonechat_id = ?",
          [groupId, from])
      else { return nil }
      conversationId = groupId
      senderId = from
      title = "\(group[0] ?? "Group") · \(member[0] ?? senderName)"
    }

    // Mute is honoured here, where the notification is made (the mailbox
    // cannot know: sealed sender). A group message that names us cuts
    // through (PROTOCOL.md "group_msg" mentions).
    let mutedUntil = db.query(
      isGroup
        ? "SELECT muted_until FROM groups WHERE id = ?"
        : "SELECT muted_until FROM contacts WHERE stonechat_id = ?",
      [conversationId])?.first ?? nil
    let nowMs = Int64(Date().timeIntervalSince1970 * 1000)
    let muted = (mutedUntil.flatMap { Int64($0) } ?? 0) > nowMs
    let mentions = payload["mentions"] as? [String] ?? []
    let silent = muted && !mentions.contains(ownId)
    let mentionsJson: String? = mentions.isEmpty
      ? nil
      : (try? JSONSerialization.data(withJSONObject: mentions))
          .flatMap { String(data: $0, encoding: .utf8) }

    // Preview-only kinds: the advanced state is dropped and the envelope
    // stays queued. Once the app has stored it (it reads the same queue),
    // the next drain must not announce it again.
    if !stores {
      if db.query("SELECT 1 FROM messages WHERE id = ?", [id]) != nil { return nil }
      if silent {
        silenced += 1
        return nil
      }
      return ShownMessage(conversationId: conversationId, title: title, body: text)
    }

    let sentAt = Self.sentAtMs(inner["sent_at"] as? String)
    var expiresAt: Int64? = nil
    if let after = payload["expire_after_ms"] as? Int, after > 0 {
      expiresAt = sentAt + Int64(after)
    }
    let reply = payload["reply_to"] as? [String: Any]
    let replyId = reply?["id"] as? String

    // Write-then-ack, atomically. INSERT OR IGNORE landing on an existing
    // row means the app already has it — ack, keep the app's session
    // state, show nothing.
    guard db.execute("BEGIN IMMEDIATE") != nil else {
      nseLog.error("could not begin transaction: \(db.lastError, privacy: .public)")
      return nil
    }
    let inserted = db.execute(
      """
      INSERT OR IGNORE INTO messages
        (id, contact_id, sender_id, outgoing, text, kind, sent_at, status,
         deleted, expires_at, reply_to_id, reply_to_sender, reply_to_preview,
         mentions)
      VALUES (?, ?, ?, 0, ?, 'text', ?, 'sent', 0, ?, ?, ?, ?, ?)
      """,
      [
        .text(id), .text(conversationId), .text(senderId), .text(text),
        .int(sentAt), .int(expiresAt), .text(replyId),
        .text(replyId == nil ? nil : reply?["sender"] as? String),
        .text(replyId == nil ? nil : reply?["preview"] as? String),
        .text(mentionsJson),
      ])
    guard let inserted else {
      nseLog.error("message insert failed: \(db.lastError, privacy: .public)")
      db.execute("ROLLBACK")
      return nil
    }
    if inserted == 0 {
      db.execute("ROLLBACK")
      socket.ack(envelopeId)
      return nil
    }
    guard
      let stateString = String(data: result.state, encoding: .utf8),
      db.execute(
        "INSERT OR REPLACE INTO sessions (peer_id, device_id, state) VALUES (?, ?, ?)",
        [.text(from), .int(Int64(fromDevice)), .text(stateString)]) != nil,
      db.execute("COMMIT") != nil
    else {
      nseLog.error("session write failed: \(db.lastError, privacy: .public)")
      db.execute("ROLLBACK")
      return nil
    }
    socket.ack(envelopeId)
    if silent {
      silenced += 1
      return nil
    }
    return ShownMessage(conversationId: conversationId, title: title, body: text)
  }

  /// Envelope `sent_at` is sender-written ISO-8601 (Dart, microsecond
  /// fraction); fall back to now like the app does.
  static func sentAtMs(_ iso: String?) -> Int64 {
    guard var s = iso else { return Int64(Date().timeIntervalSince1970 * 1000) }
    // Trim a >3-digit fraction: ISO8601DateFormatter reads millis at most.
    if let dot = s.firstIndex(of: "."), let end = s[dot...].firstIndex(where: { $0 == "Z" || $0 == "+" }) {
      let fraction = s[s.index(after: dot)..<end].prefix(3)
      s.replaceSubrange(dot..<end, with: ".\(fraction)")
    }
    let fmt = ISO8601DateFormatter()
    fmt.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
    let date = fmt.date(from: s) ?? ISO8601DateFormatter().date(from: s)
    guard let date else { return Int64(Date().timeIntervalSince1970 * 1000) }
    return Int64(date.timeIntervalSince1970 * 1000)
  }
}
