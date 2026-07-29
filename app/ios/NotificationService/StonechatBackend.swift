// The extension's view of the app's data: shared keychain (identity + DB
// key, written by flutter_secure_storage with our access group), the
// SQLCipher database in the app-group container, and the stonechat-core
// C ABI for all crypto. Read-mostly; the only writes are new message rows
// and advanced session states, committed in one transaction per envelope
// BEFORE that envelope is acked — dying mid-work leaves the queue intact.

import Foundation
import SQLCipher

let appGroupId = "group.app.stonechat.mobile"

// MARK: - keychain (flutter_secure_storage layout)

enum Keychain {
  /// Items as flutter_secure_storage writes them: generic password,
  /// service "flutter_secure_storage_service", account = key name, our
  /// app group as the access group, UTF-8 string payloads.
  static func read(_ key: String) -> String? {
    let query: [CFString: Any] = [
      kSecClass: kSecClassGenericPassword,
      kSecAttrService: "flutter_secure_storage_service",
      kSecAttrAccount: key,
      kSecAttrAccessGroup: appGroupId,
      kSecReturnData: true,
      kSecMatchLimit: kSecMatchLimitOne,
    ]
    var result: AnyObject?
    guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess,
      let data = result as? Data
    else { return nil }
    return String(data: data, encoding: .utf8)
  }
}

// MARK: - stonechat-core wrappers

enum Core {
  static func pqSeed(fromEdSeed edSeed: Data) -> Data? {
    var out = Data(count: 32)
    let rc = edSeed.withUnsafeBytes { seed in
      out.withUnsafeMutableBytes { o in
        stonechat_pq_seed_from_ed_seed(
          seed.bindMemory(to: UInt8.self).baseAddress,
          o.bindMemory(to: UInt8.self).baseAddress)
      }
    }
    return rc == 0 ? out : nil
  }

  static func unseal(pqSeed: Data, sealed: Data) -> Data? {
    var ptr: UnsafeMutablePointer<UInt8>?
    var len = 0
    let rc = pqSeed.withUnsafeBytes { seed in
      sealed.withUnsafeBytes { s in
        stonechat_unseal(
          seed.bindMemory(to: UInt8.self).baseAddress,
          s.bindMemory(to: UInt8.self).baseAddress, sealed.count,
          &ptr, &len)
      }
    }
    guard rc == 0, let p = ptr else { return nil }
    defer { stonechat_free(p, len) }
    return Data(bytes: p, count: len)
  }

  /// Returns (advancedStateJSON, plaintext) or nil on refusal — in which
  /// case the stored state is untouched and still valid.
  static func sessionDecrypt(
    stateJson: Data, headerJson: Data, nonce: Data, ciphertext: Data, ad: String
  ) -> (state: Data, plaintext: Data)? {
    var fresh = Data(count: 32)
    let ok = fresh.withUnsafeMutableBytes {
      SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!) == errSecSuccess
    }
    guard ok else { return nil }
    let adBytes = Data(ad.utf8)
    var ptr: UnsafeMutablePointer<UInt8>?
    var len = 0
    let rc = stateJson.withUnsafeBytes { state in
      headerJson.withUnsafeBytes { header in
        nonce.withUnsafeBytes { n in
          ciphertext.withUnsafeBytes { ct in
            adBytes.withUnsafeBytes { a in
              fresh.withUnsafeBytes { f in
                stonechat_session_decrypt(
                  state.bindMemory(to: UInt8.self).baseAddress, stateJson.count,
                  header.bindMemory(to: UInt8.self).baseAddress, headerJson.count,
                  n.bindMemory(to: UInt8.self).baseAddress,
                  ct.bindMemory(to: UInt8.self).baseAddress, ciphertext.count,
                  a.bindMemory(to: UInt8.self).baseAddress, adBytes.count,
                  f.bindMemory(to: UInt8.self).baseAddress,
                  &ptr, &len)
              }
            }
          }
        }
      }
    }
    guard rc == 0, let p = ptr else { return nil }
    defer { stonechat_free(p, len) }
    guard
      let result = try? JSONSerialization.jsonObject(with: Data(bytes: p, count: len))
        as? [String: Any],
      let state = result["state"],
      let plainB64 = result["plaintext"] as? String,
      let plaintext = Data(base64Encoded: plainB64),
      let stateData = try? JSONSerialization.data(withJSONObject: state)
    else { return nil }
    return (stateData, plaintext)
  }

  static func tlsFingerprintB64(certDer: Data) -> String? {
    var out = Data(count: 32)
    let rc = certDer.withUnsafeBytes { der in
      out.withUnsafeMutableBytes { o in
        stonechat_tls_fingerprint(
          der.bindMemory(to: UInt8.self).baseAddress, certDer.count,
          o.bindMemory(to: UInt8.self).baseAddress)
      }
    }
    return rc == 0 ? out.base64EncodedString() : nil
  }
}

// MARK: - SQLCipher database

final class Database {
  private var db: OpaquePointer?

  /// Opens the shared DB read-write with the flutter-side passphrase
  /// (sqflite_sqlcipher hands the same string to PRAGMA key). Returns nil
  /// when the file or key is missing — no identity yet, nothing to do.
  init?(key: String) {
    guard
      let container = FileManager.default.containerURL(
        forSecurityApplicationGroupIdentifier: appGroupId)
    else { return nil }
    let path = container.appendingPathComponent("stonechat.db").path
    guard FileManager.default.fileExists(atPath: path) else { return nil }
    guard sqlite3_open_v2(path, &db, SQLITE_OPEN_READWRITE, nil) == SQLITE_OK else {
      return nil
    }
    let keyBytes = Array(key.utf8)
    guard sqlite3_key(db, keyBytes, Int32(keyBytes.count)) == SQLITE_OK else {
      sqlite3_close(db)
      return nil
    }
    sqlite3_busy_timeout(db, 3000)
    // Cheap validity probe — wrong key fails here, not mid-drain.
    guard query("SELECT count(*) FROM sqlite_master", []) != nil else {
      sqlite3_close(db)
      return nil
    }
  }

  deinit { sqlite3_close(db) }

  /// One-row query; returns the row's columns as strings (NULL → nil).
  func query(_ sql: String, _ args: [String]) -> [String?]? {
    var stmt: OpaquePointer?
    guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else { return nil }
    defer { sqlite3_finalize(stmt) }
    let transient = unsafeBitCast(-1, to: sqlite3_destructor_type.self)
    for (i, arg) in args.enumerated() {
      sqlite3_bind_text(stmt, Int32(i + 1), arg, -1, transient)
    }
    guard sqlite3_step(stmt) == SQLITE_ROW else { return nil }
    return (0..<sqlite3_column_count(stmt)).map { col in
      sqlite3_column_text(stmt, col).map { String(cString: $0) }
    }
  }

  /// Statement with string-or-null / int64 bindings. Returns affected rows,
  /// or nil on error.
  @discardableResult
  func execute(_ sql: String, _ args: [Any?]) -> Int? {
    var stmt: OpaquePointer?
    guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else { return nil }
    defer { sqlite3_finalize(stmt) }
    let transient = unsafeBitCast(-1, to: sqlite3_destructor_type.self)
    for (i, arg) in args.enumerated() {
      let idx = Int32(i + 1)
      switch arg {
      case nil: sqlite3_bind_null(stmt, idx)
      case let v as String: sqlite3_bind_text(stmt, idx, v, -1, transient)
      case let v as Int64: sqlite3_bind_int64(stmt, idx, v)
      case let v as Int: sqlite3_bind_int64(stmt, idx, Int64(v))
      default: return nil
      }
    }
    guard sqlite3_step(stmt) == SQLITE_DONE else { return nil }
    return Int(sqlite3_changes(db))
  }

  func kvGetString(_ key: String) -> String? {
    query("SELECT v FROM kv WHERE k = ?", [key])?.first ?? nil
  }
}
