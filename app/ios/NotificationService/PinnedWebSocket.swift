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
    // The relay drains the queue immediately on attach; readiness shows up
    // as either a first frame or a clean open. sendPing round-trips the
    // handshake so we know the pinned connection actually stood up.
    let opened = DispatchSemaphore(value: 0)
    var ok = false
    task.sendPing { error in
      ok = error == nil
      opened.signal()
    }
    _ = opened.wait(timeout: .now() + timeout)
    return ok
  }

  /// Next text frame, or nil on timeout/close — timeout doubles as the
  /// "queue is drained" signal (the relay has no end marker).
  func receive(timeout: TimeInterval) -> String? {
    guard let task else { return nil }
    let done = DispatchSemaphore(value: 0)
    var frame: String?
    task.receive { result in
      if case .success(.string(let text)) = result { frame = text }
      done.signal()
    }
    guard done.wait(timeout: .now() + timeout) == .success else { return nil }
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
