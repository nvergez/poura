import XCTest
@testable import PouraCore

final class OuraProtocolTests: XCTestCase {

    // The one thing that MUST be bit-exact across the port: the auth proof. If this
    // breaks, the ring rejects authentication. Same FIPS-197 KAT the macOS tool's
    // `--selftest` uses.
    func testAES128ECBKnownAnswer() {
        let key = Data((0...15).map { UInt8($0) })
        let pt = Data([0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
                       0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff])
        let ct = OuraProtocol.aes128ECBEncrypt(key: key, block16: pt)
        XCTAssertEqual(ct?.hexString, "69c4e0d86a7b0430d8cdb78070b4c55a")
    }

    func testComputeProofShape() {
        let key = OuraProtocol.randomAuthKey()
        let nonce = Data((1...15).map { UInt8($0) })
        let proof = OuraProtocol.computeProof(authKey: key, nonce15: nonce)
        XCTAssertEqual(proof?.count, 16)
        // Wrong nonce length must be rejected, not silently padded.
        XCTAssertNil(OuraProtocol.computeProof(authKey: key, nonce15: Data(count: 14)))
    }

    func testComputeProofDeterministic() {
        // proof = AES-128-ECB(key, nonce ‖ 0x01). With a fixed key+nonce, the proof
        // is a fixed value — pin it so a future refactor of the block assembly is caught.
        let key = Data((0...15).map { UInt8($0) })                 // 000102…0f
        let nonce = Data((0...14).map { UInt8($0) })               // 0001…0e (15 bytes)
        // block = nonce ‖ 0x01 = 000102…0e01. Value pinned so a future refactor of the
        // block assembly (e.g. appending the 0x01 in the wrong place) is caught.
        let proof = OuraProtocol.computeProof(authKey: key, nonce15: nonce)
        XCTAssertEqual(proof?.hexString, "b61e6af8da7260d2214369b951bf8963")
    }

    // MARK: - Frame builders (byte-for-byte vs the documented wire format)

    func testFrameBuilders() {
        XCTAssertEqual(OuraProtocol.getAuthNonce().hexString, "2f012b")
        XCTAssertEqual(OuraProtocol.getBatteryLevel().hexString, "0c00")
        XCTAssertEqual(OuraProtocol.getFirmwareVersion().hexString, "0803000000")
        XCTAssertEqual(OuraProtocol.setBleMode(0x02).hexString, "160102")
        XCTAssertEqual(OuraProtocol.setNotification(0xbf).hexString, "1c01bf")
        XCTAssertEqual(OuraProtocol.dataFlush().hexString, "280100")
        XCTAssertEqual(OuraProtocol.featureSet(0x02, 0x03).hexString, "2f0322 0203".replacingOccurrences(of: " ", with: ""))
        XCTAssertEqual(OuraProtocol.featureSubscribe(0x02, 0x02).hexString, "2f0326 0202".replacingOccurrences(of: " ", with: ""))

        let key = Data(repeating: 0xAB, count: 16)
        XCTAssertEqual(OuraProtocol.setAuthKey(key).hexString, "2410" + String(repeating: "ab", count: 16))
    }

    func testGetEventLayout() {
        // [0x10][0x09][cursor u32 LE][max u8][flags=FFFFFFFF]
        let f = OuraProtocol.getEvent(cursor: 0x11223344, maxEvents: 0x10)
        XCTAssertEqual(f.hexString, "1009" + "44332211" + "10" + "ffffffff")
    }

    func testSyncTimeLayout() {
        let f = OuraProtocol.syncTime(unix: 0x01020304, flag: 0x04)
        XCTAssertEqual(f.hexString, "1209" + "04030201" + "00000000" + "04")
    }

    // MARK: - Response parsing + record framing

    func testParseNonceAndAuth() {
        let nonce = Data((1...15).map { UInt8($0) })
        let frame = Data([0x2f, 0x10, 0x2c]) + nonce
        let p = OuraProtocol.parseNotification(frame)
        XCTAssertEqual(p.kind, "nonce")
        XCTAssertEqual(p.payload, nonce)

        let authOK = OuraProtocol.parseNotification(Data([0x2f, 0x02, 0x2e, 0x00]))
        XCTAssertEqual(authOK.kind, "auth")
        XCTAssertEqual(authOK.payload.first, 0x00)
    }

    func testDecodeRecordsWalksTLV() {
        // Two back-to-back records: type 0x42 len=8 (4 ts + 4 payload), then 0x41 len=4.
        // [type][len][ctr_lo ctr_hi][ses_lo ses_hi][payload…]
        var buf = Data()
        buf.append(contentsOf: [0x42, 0x08, 0x01, 0x00, 0x02, 0x00, 0xde, 0xad, 0xbe, 0xef])
        buf.append(contentsOf: [0x41, 0x04, 0x05, 0x00, 0x00, 0x00])
        let (records, leftover) = OuraProtocol.decodeRecords(buf)
        XCTAssertEqual(records.count, 2)
        XCTAssertEqual(records[0].type, 0x42)
        XCTAssertEqual(records[0].counter, 1)
        XCTAssertEqual(records[0].session, 2)
        XCTAssertEqual(records[0].payload.hexString, "deadbeef")
        XCTAssertEqual(records[0].ringTimestamp, (2 << 16) | 1)
        XCTAssertEqual(records[1].type, 0x41)
        XCTAssertEqual(records[1].counter, 5)
        XCTAssertTrue(leftover.isEmpty)
    }

    func testDecodeRecordsKeepsPartialTail() {
        // A complete record followed by 3 bytes that can't frame a header+len.
        var buf = Data([0x41, 0x04, 0x00, 0x00, 0x00, 0x00])
        buf.append(contentsOf: [0x80, 0x06, 0xff]) // len=6 but only 1 payload byte present
        let (records, leftover) = OuraProtocol.decodeRecords(buf)
        XCTAssertEqual(records.count, 1)
        XCTAssertEqual(leftover.hexString, "8006ff")
    }

    func testTemperatureDecode() {
        // 0x46: 3× i16 LE /100 °C. 2800 → 28.00°C.
        let payload = Data([0xf0, 0x0a, 0xf0, 0x0a, 0xf0, 0x0a]) // 0x0af0 = 2800
        let r = OuraProtocol.Record(type: 0x46, counter: 0, session: 0, payload: payload)
        let s = OuraProtocol.decodeBiosignal(r)
        XCTAssertEqual(s, "temp=[28.00, 28.00, 28.00]°C")
    }

    func testIBIDecodeFrom0x80() {
        // Construct a beat that decodes to a plausible IBI (~880 ms → ~68 bpm).
        // ibi = (b_low << 3) | (b_high & 0x07). Want 880 = 0b1101110000.
        // low = 880 >> 3 = 110 (0x6e); high low-3-bits = 880 & 7 = 0 → b_high = 0x00.
        let payload = Data([0x6e, 0x00, 0x6e, 0x00])
        let r = OuraProtocol.Record(type: 0x80, counter: 0, session: 0, payload: payload)
        let ibis = OuraProtocol.ibiValues(r)
        XCTAssertEqual(ibis, [880, 880])
    }
}
