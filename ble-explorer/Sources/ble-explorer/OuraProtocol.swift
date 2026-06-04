// Oura Ring 4 BLE application protocol — frame builders + auth crypto.
//
// All formats VERIFIED against a real onboarding capture (see
// docs/CAPTURE_ANALYSIS.md). Write characteristic = handle 0x0015, notify = 0x0012.
//
// Frame conventions observed:
//   Direct ops:    [opcode][len][payload...]
//   Extended ops:  [0x2F][len][subtag][payload...]
//
// Auth handshake:
//   GetAuthNonce  →ring:  2F 01 2B
//   nonce resp    ring→:  2F 10 2C <15-byte nonce>
//   Authenticate  →ring:  2F 11 2D <16-byte proof>
//   auth resp     ring→:  2F 02 2E <code>   (0x00 = success)
//   proof = AES_128_ECB(auth_key, nonce ‖ 0x01)   (15-byte nonce + 0x01 = 1 block)

import Foundation
import CommonCrypto

enum OuraOpcode {
    // Direct opcodes (confirmed in capture)
    static let getFirmwareVersion: UInt8 = 0x08
    static let getBatteryLevel: UInt8 = 0x0C
    static let getEvent: UInt8 = 0x10
    static let syncTime: UInt8 = 0x12
    static let setBleMode: UInt8 = 0x16
    static let getProductInfo: UInt8 = 0x18
    static let resetMemory: UInt8 = 0x1A     // factory reset (from app code)
    static let setNotification: UInt8 = 0x1C
    static let setAuthKey: UInt8 = 0x24      // KEY_LENGTH=16, resp tag 0x25, 0x00=success
    static let dataFlush: UInt8 = 0x28
    static let ext: UInt8 = 0x2F             // extended base tag

    // Extended sub-tags (under 0x2F)
    static let extGetAuthNonce: UInt8 = 0x2B
    static let extGetAuthNonceResp: UInt8 = 0x2C
    static let extAuthenticate: UInt8 = 0x2D
    static let extAuthResp: UInt8 = 0x2E
}

enum OuraProtocol {

    /// Generate our own 16-byte auth key (cryptographically random), like the
    /// official app does (it uses a random UUID → 16 bytes).
    static func randomAuthKey() -> Data {
        var bytes = [UInt8](repeating: 0, count: 16)
        _ = SecRandomCopyBytes(kSecRandomDefault, 16, &bytes)
        return Data(bytes)
    }

    // MARK: - Frame builders

    /// SetAuthKey: [0x24][0x10][16-byte key]
    static func setAuthKey(_ key: Data) -> Data {
        precondition(key.count == 16, "auth key must be 16 bytes")
        var f = Data([OuraOpcode.setAuthKey, 0x10])
        f.append(key)
        return f
    }

    /// GetAuthNonce: [0x2F][0x01][0x2B]
    static func getAuthNonce() -> Data {
        Data([OuraOpcode.ext, 0x01, OuraOpcode.extGetAuthNonce])
    }

    /// Authenticate: [0x2F][0x11][0x2D][16-byte proof]
    static func authenticate(proof: Data) -> Data {
        precondition(proof.count == 16, "proof must be 16 bytes")
        var f = Data([OuraOpcode.ext, 0x11, OuraOpcode.extAuthenticate])
        f.append(proof)
        return f
    }

    /// Factory reset over BLE: ResetMemory(true) = [0x1A][0x01][0x01]
    static func resetMemoryFull() -> Data {
        Data([OuraOpcode.resetMemory, 0x01, 0x01])
    }

    static func getBatteryLevel() -> Data { Data([OuraOpcode.getBatteryLevel, 0x00]) }
    static func getProductInfo(sub: UInt8) -> Data { Data([OuraOpcode.getProductInfo, 0x03, sub, 0x00, 0x10]) }

    // MARK: - Auth crypto

    /// proof = AES-128-ECB(authKey, nonce ‖ 0x01), single 16-byte block.
    /// `nonce` is the 15-byte value from the ring; we append 0x01 to fill the block.
    static func computeProof(authKey: Data, nonce15: Data) -> Data? {
        precondition(authKey.count == 16, "auth key must be 16 bytes")
        guard nonce15.count == 15 else { return nil }
        var block = nonce15
        block.append(0x01)                // 15 + 1 = 16-byte plaintext block
        return aes128ECBEncrypt(key: authKey, block16: block)
    }

    /// Raw AES-128-ECB on a single 16-byte block, no padding (one block in, one out).
    static func aes128ECBEncrypt(key: Data, block16: Data) -> Data? {
        guard key.count == 16, block16.count == 16 else { return nil }
        var out = Data(count: 16)
        var moved = 0
        let status = out.withUnsafeMutableBytes { outPtr in
            block16.withUnsafeBytes { inPtr in
                key.withUnsafeBytes { keyPtr in
                    CCCrypt(
                        CCOperation(kCCEncrypt),
                        CCAlgorithm(kCCAlgorithmAES),
                        CCOptions(kCCOptionECBMode), // ECB, no padding
                        keyPtr.baseAddress, 16,
                        nil,
                        inPtr.baseAddress, 16,
                        outPtr.baseAddress, 16,
                        &moved
                    )
                }
            }
        }
        guard status == kCCSuccess, moved == 16 else { return nil }
        return out
    }

    // MARK: - Response parsing

    /// Parse a notify payload from handle 0x0012.
    /// Returns ("nonce", 15B) for GetAuthNonce resp, ("auth", [code]) for AuthResponse,
    /// ("setauthkey", [code]) for SetAuthKey resp, else ("raw", data).
    static func parseNotification(_ data: Data) -> (kind: String, payload: Data) {
        guard let first = data.first else { return ("empty", data) }
        if first == OuraOpcode.ext, data.count >= 3 {
            let sub = data[data.index(data.startIndex, offsetBy: 2)]
            let body = data.suffix(from: data.index(data.startIndex, offsetBy: 3))
            switch sub {
            case OuraOpcode.extGetAuthNonceResp: return ("nonce", Data(body))   // expect 15 bytes
            case OuraOpcode.extAuthResp:         return ("auth", Data(body))    // [code]
            default:                              return ("ext:\(String(format: "%02x", sub))", Data(body))
            }
        }
        if first == 0x25 {  // SetAuthKey response tag; result at offset 2
            let code = data.count >= 3 ? data[data.index(data.startIndex, offsetBy: 2)] : 0xFF
            return ("setauthkey", Data([code]))
        }
        return ("raw", data)
    }
}
