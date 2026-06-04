// Minimal Keychain wrapper for the ring's auth_key.
// Stores the 16-byte key encrypted at rest by the macOS Keychain (much safer than
// the plaintext secrets/ file). Service/account identify our entry.

import Foundation
import Security

enum Keychain {
    static let service = "com.poura.oura-ring"
    static let account = "auth_key"

    /// Store (or overwrite) the auth key. Returns true on success.
    @discardableResult
    static func storeAuthKey(_ key: Data) -> Bool {
        // Delete any existing item first (SecItemUpdate is fiddlier).
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
        SecItemDelete(query as CFDictionary)

        var add = query
        add[kSecValueData as String] = key
        add[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlocked
        let status = SecItemAdd(add as CFDictionary, nil)
        return status == errSecSuccess
    }

    /// Load the auth key, or nil if absent.
    static func loadAuthKey() -> Data? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var out: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &out)
        guard status == errSecSuccess, let data = out as? Data, data.count == 16 else { return nil }
        return data
    }

    @discardableResult
    static func deleteAuthKey() -> Bool {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
        return SecItemDelete(query as CFDictionary) == errSecSuccess
    }
}
