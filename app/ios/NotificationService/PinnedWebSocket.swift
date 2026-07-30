// WebSocket to the user's own mailbox with the Stonechat trust model:
// the relay's self-signed certificate is accepted iff BLAKE2b-256 of its
// DER equals the pinned fingerprint the owner vouched for — no CAs, no
// hostnames (PROTOCOL.md "Transport"; the app's counterpart is
// api.dart's badCertificateCallback). Synchronous API: the extension has
// one job and a 30-second budget, semaphores keep the control flow flat.

import Foundation

final class PinnedWebSocket: NSObject, URLSessionDelegate {
  private let address: String  // https://host:port, scheme swapped to wss
  private let token: String
  private let tlsFp: String
  private var session: URLSession?
  private var task: URLSessionWebSocketTask?

  init(address: String, token: String, tlsFp: String) {
    self.address = address
    self.token = token
    self.tlsFp = tlsFp
  }

  /// Opens the socket. Deliberately does NOT round-trip a ping first: the
  /// relay splits its socket (relay/src/ws.rs), so tungstenite's automatic
  /// Pong is queued on a write half that is only flushed when the relay
  /// has envelopes to send — a ping can go unanswered on a perfectly
  /// healthy connection. Readiness is proven by the first frame instead,
  /// and a dead connection surfaces as a receive error.
  func connect(timeout: TimeInterval) -> Bool {
    let ws = address
      .replacingOccurrences(of: "https://", with: "wss://")
      .replacingOccurrences(of: "http://", with: "ws://")
    guard let url = URL(string: "\(ws)/ws?token=\(token)") else { return false }
    let config = URLSessionConfiguration.ephemeral
    config.timeoutIntervalForRequest = timeout
    let session = URLSession(configuration: config, delegate: self, delegateQueue: nil)
    self.session = session
    let task = session.webSocketTask(with: url)
    self.task = task
    task.resume()
    return true
  }

  enum Frame {
    case text(String)
    /// Nothing arrived in the window — with no end marker from the relay,
    /// this is what "the queue is drained" looks like.
    case idle
    /// The connection failed (TLS pin, auth, network). Carries the reason.
    case failed(String)
  }

  func receive(timeout: TimeInterval) -> Frame {
    guard let task else { return .failed("no socket") }
    let done = DispatchSemaphore(value: 0)
    var frame = Frame.idle
    task.receive { result in
      switch result {
      case .success(.string(let text)): frame = .text(text)
      case .success: frame = .idle  // binary/unknown — the relay sends text
      case .failure(let error): frame = .failed(error.localizedDescription)
      }
      done.signal()
    }
    guard done.wait(timeout: .now() + timeout) == .success else { return .idle }
    return frame
  }

  /// Ack ⇒ the relay deletes the envelope (and its blob). Fire-and-forget:
  /// a lost ack merely redelivers later, and the app dedupes by id.
  func ack(_ envelopeId: String) {
    task?.send(.string("{\"ack\":\"\(envelopeId)\"}")) { _ in }
  }

  func close() {
    task?.cancel(with: .normalClosure, reason: nil)
    session?.invalidateAndCancel()
  }

  // MARK: pinning

  func urlSession(
    _ session: URLSession,
    didReceive challenge: URLAuthenticationChallenge,
    completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
  ) {
    // Self-signed by design: the fingerprint IS the trust decision, so the
    // system evaluation result is irrelevant — matching pin ⇒ proceed,
    // anything else ⇒ hard fail.
    guard
      challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
      let trust = challenge.protectionSpace.serverTrust,
      let chain = SecTrustCopyCertificateChain(trust) as? [SecCertificate],
      let leaf = chain.first
    else {
      completionHandler(.cancelAuthenticationChallenge, nil)
      return
    }
    let der = SecCertificateCopyData(leaf) as Data
    if Core.tlsFingerprintB64(certDer: der) == tlsFp {
      completionHandler(.useCredential, URLCredential(trust: trust))
    } else {
      completionHandler(.cancelAuthenticationChallenge, nil)
    }
  }
}
