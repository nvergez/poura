// Minimal Keychain wrapper for the ring's auth_key.
// Stores the 16-byte key encrypted at rest by the system Keychain (much safer than
// a plaintext file). Service/account identify our entry.
//
// iOS note vs the macOS tool: we use `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`
// so the key is NOT synced to iCloud Keychain and never leaves this device — the
// auth_key is the only thing standing between an attacker and the ring's biosignals,
// so it should not be backed up off-device. (The macOS tool uses the syncable
// `…WhenUnlocked`; this is the one intentional behavioural difference.)

import Foundation
import Security

public enum Keychain {
    public static let service = "com.poura.oura-ring"
    public static let account = "auth_key"

    /// Store (or overwrite) the auth key. Returns true on success.
    @discardableResult
    public static func storeAuthKey(_ key: Data) -> Bool {
        // Delete any existing item first (SecItemUpdate is fiddlier).
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
        SecItemDelete(query as CFDictionary)

        var add = query
        add[kSecValueData as String] = key
        add[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        let status = SecItemAdd(add as CFDictionary, nil)
        return status == errSecSuccess
    }

    /// Load the auth key, or nil if absent.
    public static func loadAuthKey() -> Data? {
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
    public static func deleteAuthKey() -> Bool {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
        return SecItemDelete(query as CFDictionary) == errSecSuccess
    }
}
