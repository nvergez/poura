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

    /// GetFirmwareVersion: observed in capture as `08 03 00 00 00`.
    static func getFirmwareVersion() -> Data { Data([OuraOpcode.getFirmwareVersion, 0x03, 0x00, 0x00, 0x00]) }

    /// SetBleMode: the app sends `16 01 02` right after auth. Appears to switch the
    /// ring into the "connected/active" mode that unlocks info + streaming.
    static func setBleMode(_ mode: UInt8) -> Data { Data([OuraOpcode.setBleMode, 0x01, mode]) }

    /// SyncTime (0x12): `12 09 <unix_ts LE u32> 00 00 00 00 <tz/flag>`. The app sends
    /// the current unix time so the ring can anchor its tick counter to wall-clock.
    static func syncTime(unix: UInt32, flag: UInt8 = 0x04) -> Data {
        var f = Data([OuraOpcode.syncTime, 0x09])
        var le = unix.littleEndian
        withUnsafeBytes(of: &le) { f.append(contentsOf: $0) }   // 4 bytes
        f.append(contentsOf: [0x00, 0x00, 0x00, 0x00])          // observed padding
        f.append(flag)
        return f
    }

    /// SetNotification (0x1C): app sends `1c 01 bf` — enable the notification/event
    /// firehose (bitmask 0xbf selects which record classes the ring pushes).
    static func setNotification(_ mask: UInt8 = 0xbf) -> Data { Data([OuraOpcode.setNotification, 0x01, mask]) }

    /// data_flush / CheckSleepAnalysis (0x28): app sends `28 01 00` before GetEvent.
    static func dataFlush() -> Data { Data([OuraOpcode.dataFlush, 0x01, 0x00]) }

    // MARK: - Feature subscription (ext 0x2F) — measurement enable

    /// The app, right after battery, runs a feature get/set/subscribe block before
    /// data_flush. Decoded byte-for-byte from poura-onboarding.btsnoop (frames 926-992):
    ///   get:        2f 02 20 <featureID>          → resp 2f 06 21 <id> <4B value>
    ///   set:        2f 03 22 <featureID> <value>  → resp 2f 03 23 <id> <value>
    ///   subscribe:  2f 03 26 <featureID> <value>  → resp 2f 03 27 <id> <code>
    /// The decisive one before the stream opens is `2f 03 26 02 02` (subscribe
    /// feature 0x02 = 0x02), preceded by `2f 03 22 02 03` (set feature 0x02 = 0x03).
    static func featureGet(_ id: UInt8) -> Data { Data([OuraOpcode.ext, 0x02, 0x20, id]) }
    static func featureSet(_ id: UInt8, _ value: UInt8) -> Data { Data([OuraOpcode.ext, 0x03, 0x22, id, value]) }
    static func featureSubscribe(_ id: UInt8, _ value: UInt8) -> Data { Data([OuraOpcode.ext, 0x03, 0x26, id, value]) }

    /// GetEvent (0x10): history fetch by ringTimestamp cursor.
    /// Wire layout (11 bytes, per open_ring PROTOCOL.md, to be validated on the ring):
    ///   [0x10][0x09][cursor u32 LE][max_events u8][flags u32 LE = 0xFFFFFFFF]
    /// `cursor` = ringTimestamp to resume after (0 = full dump); `maxEvents` ≤255 to
    /// fetch, 0 = ack-only (advance the cursor without data).
    static func getEvent(cursor: UInt32, maxEvents: UInt8 = 0xFF) -> Data {
        var f = Data([OuraOpcode.getEvent, 0x09])
        var le = cursor.littleEndian
        withUnsafeBytes(of: &le) { f.append(contentsOf: $0) }   // 4 bytes cursor
        f.append(maxEvents)                                     // 1 byte max_events
        f.append(contentsOf: [0xFF, 0xFF, 0xFF, 0xFF])          // 4 bytes flags
        return f
    }

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

    // MARK: - Info-response decoding (battery / firmware / product)

    /// A decoded TLV record from the stream / history firehose.
    struct Record {
        let type: UInt8
        let counter: UInt16
        let session: UInt16
        let payload: Data
        var ringTimestamp: UInt32 { (UInt32(session) << 16) | UInt32(counter) }
    }

    /// Human label for a record type. Names are from the public RE notes
    /// (open_ring / ringverse) and are to be re-validated against our own data.
    static func recordTypeName(_ t: UInt8) -> String {
        switch t {
        case 0x33: return "accel"
        case 0x41: return "boot/start"
        case 0x42: return "time-anchor"
        case 0x43: return "diag-log"      // ASCII diagnostic text (observed in our dump)
        case 0x45: return "state-change"
        case 0x46: return "temp"          // 3× i16 LE /100 = °C
        case 0x47: return "motion"        // compact 3-axis accel
        case 0x53: return "wear-state"
        case 0x60: return "IBI+amp"       // bit-packed IBI ms + amplitude
        case 0x61: return "debug-data"    // payload[0] = sub-dispatch
        case 0x79: return "AFE-tuning"    // [sub][idx][u16 LE samples]
        case 0x80: return "IBI-quality"
        case 0x81: return "raw-PPG"
        case 0x85: return "RTC-beacon"
        default:   return "type-0x\(String(format: "%02x", t))"
        }
    }

    /// Decode a buffer of back-to-back TLV records:
    ///   [type:1][len:1][ctr_lo][ctr_hi][ses_lo][ses_hi][payload(len-4)...]
    /// `len` counts the 4 timestamp bytes + payload (per the public spec). We parse
    /// defensively: a bad length stops the walk rather than reading out of bounds.
    /// Returns the records plus any trailing bytes we couldn't frame (for debugging).
    static func decodeRecords(_ buf: Data) -> (records: [Record], leftover: Data) {
        var records: [Record] = []
        let bytes = [UInt8](buf)
        var i = 0
        while i + 2 <= bytes.count {
            let type = bytes[i]
            let len = Int(bytes[i + 1])
            // len must cover the 4 timestamp bytes; payload = len - 4.
            guard len >= 4, i + 2 + len <= bytes.count else { break }
            let ctr = UInt16(bytes[i + 2]) | (UInt16(bytes[i + 3]) << 8)
            let ses = UInt16(bytes[i + 4]) | (UInt16(bytes[i + 5]) << 8)
            let payload = Data(bytes[(i + 6)..<(i + 2 + len)])
            records.append(Record(type: type, counter: ctr, session: ses, payload: payload))
            i += 2 + len
        }
        return (records, Data(bytes[i...]))
    }

    /// Human decode of the physiological record payloads we VERIFIED against the
    /// onboarding capture (see JOURNAL 2026-06-05b). Returns nil for types we don't
    /// (yet) decode — the caller then just prints the raw payload hex.
    ///
    /// Formats (from capture + open_ring decoders.py, to be re-validated on worn data):
    ///  - 0x46 TEMP:   3× i16 LE, value/100 = °C.
    ///  - 0x80 GREEN_IBI_QUALITY: N× u16 LE; bits 0-10 = IBI ms, 11-13 = qual_a,
    ///    14-15 = qual_b. A beat is "clean" when qual_a ≤ 1 and qual_b == 0.
    ///  - 0x60 IBI+amp: bit-packed 6×(11-bit IBI ms, amplitude) — left raw for now
    ///    (packing needs worn-data validation; flagged rather than guessed).
    static func decodeBiosignal(_ r: Record) -> String? {
        let p = [UInt8](r.payload)
        switch r.type {
        case 0x46:   // temperature
            guard p.count >= 6 else { return nil }
            func t(_ i: Int) -> Double { Double(Int16(bitPattern: UInt16(p[i]) | (UInt16(p[i+1]) << 8))) / 100.0 }
            return String(format: "temp=[%.2f, %.2f, %.2f]°C", t(0), t(2), t(4))
        case 0x80:   // green-LED IBI quality — 7× u16 LE. The exact bit packing of
            // IBI-ms vs quality is NOT yet validated against ground truth (the
            // bits-0..10 split produces incoherent intervals on real data), so we
            // print the raw u16 words rather than asserting wrong "ms" values.
            guard p.count >= 2 else { return nil }
            var words: [String] = []
            var i = 0
            while i + 1 < p.count {
                let w = UInt16(p[i]) | (UInt16(p[i+1]) << 8)
                words.append(String(format: "0x%04x", w))
                i += 2
            }
            return "IBI-words(u16 LE, packing TBD)=[\(words.joined(separator: " "))]"
        default:
            return nil
        }
    }
}
