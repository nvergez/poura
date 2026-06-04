// poura — BLE explorer (macOS, read-only)
//
// Goal: scan, connect to the Oura ring, and dump its full GATT tree
// (services + characteristics + readable values). READ-ONLY: this tool never
// writes to the ring. It is the observation foundation before any takeover work.
//
// Usage:
//   swift run ble-explorer                 # scan all, list devices for 12s
//   swift run ble-explorer --oura          # scan only for the Oura service, auto-connect & dump
//   swift run ble-explorer --connect <UUID>  # connect to a specific peripheral identifier & dump
//   swift run ble-explorer --name <substr> # auto-connect to first device whose name matches
//
// Notes:
//  - macOS will prompt for Bluetooth permission on first run.
//  - The iOS simulator has no Bluetooth; this runs on real macOS hardware.

import Foundation
import CoreBluetooth

// Force line-buffered / immediate flush so output is visible even when stdout is
// redirected to a file (otherwise libc block-buffers and we see nothing live).
setbuf(stdout, nil)

// Oura Ring 4 GATT identifiers — CONFIRMED against the real ring + btsnoop capture.
// Service 98ED0001; write commands → 98ED0002 (handle 0x0015), responses notify on
// 98ED0003 (handle 0x0012).
let ouraServiceUUID = CBUUID(string: "98ed0001-a541-11e4-b6a0-0002a5d5c51b")
let ouraWriteCharUUID = CBUUID(string: "98ed0002-a541-11e4-b6a0-0002a5d5c51b")
let ouraNotifyCharUUID = CBUUID(string: "98ed0003-a541-11e4-b6a0-0002a5d5c51b")

// Standard services worth reading for context (cleartext, no auth needed):
let batteryServiceUUID = CBUUID(string: "180F")
let deviceInfoServiceUUID = CBUUID(string: "180A")

enum Mode {
    case scanAll
    case ouraOnly
    case connect(uuid: UUID)
    case byName(substring: String)
    case takeover         // scan ring (pairing mode) → bond → SetAuthKey(ours) → Authenticate
    case auth(key: Data)  // reconnect (no pairing mode) → GetAuthNonce → Authenticate with our saved key
    case selftest         // validate AES-128-ECB against a known FIPS-197 vector, no BLE
}

/// Parse a 32-hex-char string into 16 bytes.
func hexToData(_ s: String) -> Data? {
    let clean = s.filter { $0.isHexDigit }
    guard clean.count == 32 else { return nil }
    var d = Data(); var idx = clean.startIndex
    while idx < clean.endIndex {
        let next = clean.index(idx, offsetBy: 2)
        guard let b = UInt8(clean[idx..<next], radix: 16) else { return nil }
        d.append(b); idx = next
    }
    return d
}

func parseArgs() -> (mode: Mode, scanSeconds: Double) {
    var mode: Mode = .scanAll
    var scanSeconds = 12.0
    let args = Array(CommandLine.arguments.dropFirst())
    var i = 0
    while i < args.count {
        switch args[i] {
        case "--oura":
            mode = .ouraOnly
        case "--takeover":
            mode = .takeover
        case "--auth":
            if i + 1 < args.count, let k = hexToData(args[i + 1]) {
                mode = .auth(key: k); i += 1
            } else {
                FileHandle.standardError.write(Data("--auth requires a 32-hex-char (16-byte) key\n".utf8))
                exit(2)
            }
        case "--selftest":
            mode = .selftest
        case "--connect":
            if i + 1 < args.count, let u = UUID(uuidString: args[i + 1]) {
                mode = .connect(uuid: u); i += 1
            } else {
                FileHandle.standardError.write(Data("--connect requires a valid peripheral UUID\n".utf8))
                exit(2)
            }
        case "--name":
            if i + 1 < args.count {
                mode = .byName(substring: args[i + 1]); i += 1
            } else {
                FileHandle.standardError.write(Data("--name requires a substring\n".utf8))
                exit(2)
            }
        case "--seconds":
            if i + 1 < args.count, let s = Double(args[i + 1]) {
                scanSeconds = s; i += 1
            }
        default:
            FileHandle.standardError.write(Data("Unknown arg: \(args[i])\n".utf8))
        }
        i += 1
    }
    return (mode, scanSeconds)
}

// Human-readable description of CBCharacteristicProperties.
func describeProperties(_ p: CBCharacteristicProperties) -> String {
    var parts: [String] = []
    if p.contains(.broadcast) { parts.append("broadcast") }
    if p.contains(.read) { parts.append("read") }
    if p.contains(.writeWithoutResponse) { parts.append("writeNoResp") }
    if p.contains(.write) { parts.append("write") }
    if p.contains(.notify) { parts.append("notify") }
    if p.contains(.indicate) { parts.append("indicate") }
    if p.contains(.authenticatedSignedWrites) { parts.append("signedWrite") }
    if p.contains(.extendedProperties) { parts.append("extended") }
    return parts.isEmpty ? "(none)" : parts.joined(separator: ",")
}

func hex(_ data: Data) -> String {
    data.map { String(format: "%02x", $0) }.joined(separator: " ")
}

func ascii(_ data: Data) -> String {
    String(data.map { (0x20...0x7e).contains($0) ? Character(UnicodeScalar($0)) : "." })
}

final class Explorer: NSObject, CBCentralManagerDelegate, CBPeripheralDelegate {
    let mode: Mode
    let scanSeconds: Double
    var central: CBCentralManager!
    var target: CBPeripheral?
    var discovered: [UUID: (peripheral: CBPeripheral, name: String, rssi: Int)] = [:]

    // Track pending reads so we know when the dump is complete.
    var pendingReads = 0
    var didFinishDiscovery = false

    // Takeover state
    var writeChar: CBCharacteristic?      // Oura command char (handle 0x0015)
    var notifyChar: CBCharacteristic?     // Oura response char (handle 0x0012)
    var myAuthKey: Data = OuraProtocol.randomAuthKey()
    enum TakeoverStep { case idle, notifyEnabled, sentSetAuthKey, sentNonce, sentAuth, done }
    var takeoverStep: TakeoverStep = .idle

    init(mode: Mode, scanSeconds: Double) {
        self.mode = mode
        self.scanSeconds = scanSeconds
        super.init()
        central = CBCentralManager(delegate: self, queue: nil)
    }

    func log(_ s: String) { print(s) }

    // MARK: CBCentralManagerDelegate

    func centralManagerDidUpdateState(_ central: CBCentralManager) {
        switch central.state {
        case .poweredOn:
            log("[ble] Bluetooth powered on. Starting scan…")
            startScan()
        case .poweredOff:
            log("[ble] Bluetooth is powered OFF. Enable it and re-run.")
            exit(1)
        case .unauthorized:
            log("[ble] Bluetooth unauthorized. Grant permission to the terminal/binary in System Settings → Privacy & Security → Bluetooth.")
            exit(1)
        case .unsupported:
            log("[ble] Bluetooth unsupported on this machine.")
            exit(1)
        default:
            log("[ble] Bluetooth state: \(central.state.rawValue) (waiting…)")
        }
    }

    func startScan() {
        switch mode {
        case .connect(let uuid):
            // Try to retrieve a known peripheral directly.
            let known = central.retrievePeripherals(withIdentifiers: [uuid])
            if let p = known.first {
                log("[ble] Retrieved peripheral \(uuid). Connecting…")
                connect(p)
                return
            }
            log("[ble] Peripheral \(uuid) not cached; scanning to find it (waiting for a strong-enough advert)…")
            central.scanForPeripherals(withServices: nil, options: [CBCentralManagerScanOptionAllowDuplicatesKey: true])
        case .ouraOnly, .takeover, .auth:
            if case .takeover = mode {
                log("[takeover] ⚠️ This will SET OUR OWN auth_key on the ring. Only run on a FACTORY-RESET ring.")
                log("[takeover] Put the ring in PAIRING MODE: remove from charger and put it back (white blinking light).")
            }
            if case .auth = mode {
                log("[auth] Persistence test: reconnect (no pairing mode needed) → authenticate with our saved key.")
            }
            log("[ble] Scanning for Oura service \(ouraServiceUUID.uuidString)…")
            central.scanForPeripherals(withServices: [ouraServiceUUID], options: nil)
            DispatchQueue.main.asyncAfter(deadline: .now() + 4) { [weak self] in
                guard let self, self.target == nil else { return }
                self.log("[ble] No Oura-service advert yet; widening to a full scan…")
                self.central.stopScan()
                self.central.scanForPeripherals(withServices: nil, options: nil)
            }
        case .selftest:
            break // handled before BLE starts
        case .byName, .scanAll:
            log("[ble] Scanning all peripherals for \(Int(scanSeconds))s…")
            central.scanForPeripherals(withServices: nil, options: [CBCentralManagerScanOptionAllowDuplicatesKey: false])
        }

        // For pure listing modes, stop after the window and print a summary.
        if case .scanAll = mode {
            DispatchQueue.main.asyncAfter(deadline: .now() + scanSeconds) { [weak self] in
                self?.finishScanListing()
            }
        }
    }

    func finishScanListing() {
        central.stopScan()
        log("\n=== Discovered peripherals (\(discovered.count)) ===")
        let sorted = discovered.values.sorted { $0.rssi > $1.rssi }
        for d in sorted {
            log(String(format: "  %@  rssi=%-4d  %@", d.peripheral.identifier.uuidString, d.rssi, d.name))
        }
        log("\nTip: re-run with `--connect <UUID>` to dump a device's GATT, or `--oura` to auto-target the ring.")
        exit(0)
    }

    func centralManager(_ central: CBCentralManager, didDiscover peripheral: CBPeripheral,
                        advertisementData: [String : Any], rssi RSSI: NSNumber) {
        let advName = (advertisementData[CBAdvertisementDataLocalNameKey] as? String) ?? peripheral.name ?? "(unknown)"
        let svcs = (advertisementData[CBAdvertisementDataServiceUUIDsKey] as? [CBUUID])?.map { $0.uuidString }.joined(separator: ",") ?? ""
        let isNew = discovered[peripheral.identifier] == nil
        discovered[peripheral.identifier] = (peripheral, advName, RSSI.intValue)

        // Manufacturer data is gold for fingerprinting the ring (Oura company ID, etc.)
        var mfg = ""
        if let m = advertisementData[CBAdvertisementDataManufacturerDataKey] as? Data {
            mfg = hex(m)
        }

        let connectable = (advertisementData[CBAdvertisementDataIsConnectable] as? NSNumber)?.boolValue
        let connStr = connectable == nil ? "?" : (connectable! ? "YES" : "NO")

        switch mode {
        case .scanAll:
            // Live print ONLY for newly-seen devices (avoid the duplicate spam),
            // and always print devices that look ring-like or carry mfg data.
            let ringLike = advName.lowercased().contains("oura")
                || (advertisementData[CBAdvertisementDataServiceUUIDsKey] as? [CBUUID])?.contains(ouraServiceUUID) == true
            if ringLike {
                log(String(format: "[scan] ⟵RING? %@  rssi=%-4d  %@  svc=[%@]  mfg=[%@]  connectable=%@",
                           peripheral.identifier.uuidString, RSSI.intValue, advName, svcs, mfg, connStr))
            } else if isNew {
                log(String(format: "[scan] %@  rssi=%-4d  %@  svc=[%@]%@",
                           peripheral.identifier.uuidString, RSSI.intValue, advName, svcs,
                           mfg.isEmpty ? "" : "  mfg=[\(mfg)]"))
            }
        case .ouraOnly, .takeover, .auth:
            let advertisesOura = (advertisementData[CBAdvertisementDataServiceUUIDsKey] as? [CBUUID])?.contains(ouraServiceUUID) ?? false
            if advertisesOura || advName.lowercased().contains("oura") {
                log("[ble] Found candidate Oura device: \(advName) [\(peripheral.identifier.uuidString)] rssi=\(RSSI.intValue) connectable=\(connStr)")
                central.stopScan()
                connect(peripheral)
            }
        case .selftest:
            break
        case .byName(let sub):
            if advName.lowercased().contains(sub.lowercased()) {
                log("[ble] Name match: \(advName) [\(peripheral.identifier.uuidString)]")
                central.stopScan()
                connect(peripheral)
            }
        case .connect(let uuid):
            if peripheral.identifier == uuid {
                central.stopScan()
                connect(peripheral)
            }
        }
    }

    var connecting = false
    func connect(_ peripheral: CBPeripheral) {
        guard !connecting else { return }
        connecting = true
        central.stopScan()
        target = peripheral
        peripheral.delegate = self
        log("[ble] Connecting to \(peripheral.identifier.uuidString) (\(peripheral.name ?? "?"))…")
        central.connect(peripheral, options: nil)
        // Connection watchdog: if not connected in 15s, log it (the ring may be
        // weak-signal on the charger — move it closer to the Mac).
        DispatchQueue.main.asyncAfter(deadline: .now() + 15) { [weak self] in
            guard let self else { return }
            if self.target?.state != .connected {
                self.log("[ble] Still not connected after 15s (state=\(self.target?.state.rawValue ?? -1)). Weak signal? Move the ring/charger closer to the Mac. Retrying scan…")
                self.central.connect(peripheral, options: nil)
            }
        }
    }

    func centralManager(_ central: CBCentralManager, didConnect peripheral: CBPeripheral) {
        connecting = true
        log("[ble] ✅ Connected. Name=\(peripheral.name ?? "(nil)"). Discovering services…")
        peripheral.discoverServices(nil) // discover ALL services
    }

    func centralManager(_ central: CBCentralManager, didFailToConnect peripheral: CBPeripheral, error: Error?) {
        log("[ble] Failed to connect: \(error?.localizedDescription ?? "unknown")")
        exit(1)
    }

    func centralManager(_ central: CBCentralManager, didDisconnectPeripheral peripheral: CBPeripheral, error: Error?) {
        log("[ble] Disconnected: \(error?.localizedDescription ?? "clean")")
    }

    // MARK: CBPeripheralDelegate

    func peripheral(_ peripheral: CBPeripheral, didDiscoverServices error: Error?) {
        if let error { log("[ble] Service discovery error: \(error.localizedDescription)"); exit(1) }
        guard let services = peripheral.services else { log("[ble] No services."); exit(0) }
        log("\n=== GATT services (\(services.count)) for \(peripheral.identifier.uuidString) ===")
        for s in services {
            let marker = s.uuid == ouraServiceUUID ? "  ⟵ OURA CUSTOM SERVICE" : ""
            log("• Service \(s.uuid.uuidString)\(marker)")
            peripheral.discoverCharacteristics(nil, for: s)
        }
    }

    func peripheral(_ peripheral: CBPeripheral, didDiscoverCharacteristicsFor service: CBService, error: Error?) {
        if let error { log("[ble]   char discovery error for \(service.uuid): \(error.localizedDescription)"); return }
        guard let chars = service.characteristics else { return }
        for c in chars {
            let marker = c.uuid == ouraNotifyCharUUID ? "  ⟵ OURA NOTIFY" : ""
            log("    └ char \(c.uuid.uuidString)  props=[\(describeProperties(c.properties))]\(marker)")

            // In takeover/auth mode, capture the EXACT Oura write + notify chars by
            // UUID (98ED0004 also has write+notify — match UUIDs explicitly).
            if isHandshake, service.uuid == ouraServiceUUID {
                if c.uuid == ouraNotifyCharUUID { notifyChar = c }
                if c.uuid == ouraWriteCharUUID { writeChar = c }
            }

            // Read any readable characteristic (read-only) — NOT during a handshake.
            if c.properties.contains(.read), !isHandshake {
                pendingReads += 1
                peripheral.readValue(for: c)
            }
            peripheral.discoverDescriptors(for: c)
        }

        if isHandshake, let nc = notifyChar, writeChar != nil, takeoverStep == .idle {
            log("[\(isTakeover ? "takeover" : "auth")] Found Oura write + notify chars. Enabling notifications…")
            peripheral.setNotifyValue(true, for: nc)
        } else if !isHandshake {
            checkDone(peripheral)
        }
    }

    var isTakeover: Bool { if case .takeover = mode { return true } else { return false } }
    var isAuthOnly: Bool { if case .auth = mode { return true } else { return false } }
    var isHandshake: Bool { isTakeover || isAuthOnly }

    func peripheral(_ peripheral: CBPeripheral, didUpdateNotificationStateFor characteristic: CBCharacteristic, error: Error?) {
        guard isHandshake, characteristic == notifyChar else { return }
        let tag = isTakeover ? "takeover" : "auth"
        if let error { log("[\(tag)] Failed to enable notifications: \(error.localizedDescription)"); exit(1) }
        guard takeoverStep == .idle else { return }
        takeoverStep = .notifyEnabled

        if case .auth(let key) = mode {
            // Persistence test: skip SetAuthKey, authenticate with the saved key.
            myAuthKey = key
            log("[auth] Notifications enabled. Authenticating with saved key \(hex(myAuthKey))")
            log("[auth] → GetAuthNonce (2F 01 2B)…")
            takeoverStep = .sentNonce
            write(OuraProtocol.getAuthNonce())
        } else {
            log("[takeover] Notifications enabled. My auth_key = \(hex(myAuthKey))")
            log("[takeover] → SetAuthKey (0x24)…")
            takeoverStep = .sentSetAuthKey
            write(OuraProtocol.setAuthKey(myAuthKey))
        }
    }

    func write(_ data: Data) {
        guard let wc = writeChar, let p = target else { return }
        log("[takeover]   write: \(hex(data))")
        // Use withResponse if supported, else withoutResponse.
        let type: CBCharacteristicWriteType = wc.properties.contains(.write) ? .withResponse : .withoutResponse
        p.writeValue(data, for: wc, type: type)
    }

    func peripheral(_ peripheral: CBPeripheral, didUpdateValueFor characteristic: CBCharacteristic, error: Error?) {
        // Takeover/auth: drive the handshake from notify responses.
        if isHandshake, characteristic == notifyChar {
            guard let data = characteristic.value else { return }
            let parsed = OuraProtocol.parseNotification(data)
            log("[takeover]   notify: \(hex(data))  → \(parsed.kind)")
            handleTakeoverNotification(parsed, peripheral: peripheral)
            return
        }
        pendingReads = max(0, pendingReads - 1)
        if let error {
            log("      [read] \(characteristic.uuid.uuidString): error \(error.localizedDescription)")
        } else if let data = characteristic.value {
            log("      [read] \(characteristic.uuid.uuidString): \(data.count)B  hex=[\(hex(data))]  ascii=\"\(ascii(data))\"")
        }
        checkDone(peripheral)
    }

    func handleTakeoverNotification(_ parsed: (kind: String, payload: Data), peripheral: CBPeripheral) {
        switch parsed.kind {
        case "setauthkey":
            let code = parsed.payload.first ?? 0xFF
            if code == 0x00 || code == 0x05 {
                log("[takeover] ✅ SetAuthKey accepted (code=0x\(String(format: "%02x", code))). → GetAuthNonce…")
                takeoverStep = .sentNonce
                write(OuraProtocol.getAuthNonce())
            } else {
                log("[takeover] ❌ SetAuthKey REJECTED (code=0x\(String(format: "%02x", code))). Ring likely NOT factory-reset (still claimed). Stopping.")
                finishTakeover(peripheral, success: false)
            }
        case "nonce":
            let nonce = parsed.payload
            guard nonce.count == 15 else {
                log("[takeover] ❌ Unexpected nonce length \(nonce.count) (expected 15). Stopping."); finishTakeover(peripheral, success: false); return
            }
            guard let proof = OuraProtocol.computeProof(authKey: myAuthKey, nonce15: nonce) else {
                log("[takeover] ❌ Proof computation failed."); finishTakeover(peripheral, success: false); return
            }
            log("[takeover] nonce=\(hex(nonce)) → proof=\(hex(proof)). → Authenticate…")
            takeoverStep = .sentAuth
            write(OuraProtocol.authenticate(proof: proof))
        case "auth":
            let code = parsed.payload.first ?? 0xFF
            if code == 0x00 {
                log("[takeover] 🎉🎉 AUTHENTICATED with OUR key! The ring is now ours. (code=0x00)")
                finishTakeover(peripheral, success: true)
            } else {
                let meaning = ["0x01":"auth error", "0x02":"in factory reset", "0x03":"not original onboarded device"]["0x\(String(format: "%02x", code))"] ?? "unknown"
                log("[takeover] ❌ Authenticate failed (code=0x\(String(format: "%02x", code)) = \(meaning)).")
                finishTakeover(peripheral, success: false)
            }
        default:
            break // ignore other notifications during takeover
        }
    }

    func finishTakeover(_ peripheral: CBPeripheral, success: Bool) {
        guard takeoverStep != .done else { return }
        takeoverStep = .done
        let tag = isTakeover ? "takeover" : "auth"
        if success {
            if isAuthOnly {
                log("\n[auth] ✅ PERSISTENCE CONFIRMED — the ring remembered our key. We can re-authenticate anytime.")
            } else {
                log("\n[takeover] ✅ SUCCESS. Save THIS key to talk to the ring from now on:")
                log("[takeover]   AUTH_KEY=\(hex(myAuthKey).replacingOccurrences(of: " ", with: ""))")
            }
        } else {
            log("\n[\(tag)] ✗ Did not complete. See messages above.")
        }
        central.cancelPeripheralConnection(peripheral)
        DispatchQueue.main.asyncAfter(deadline: .now() + 1) { exit(success ? 0 : 1) }
    }

    func peripheral(_ peripheral: CBPeripheral, didDiscoverDescriptorsFor characteristic: CBCharacteristic, error: Error?) {
        if let descs = characteristic.descriptors, !descs.isEmpty {
            for d in descs {
                log("        · descriptor \(d.uuid.uuidString)")
            }
        }
    }

    var doneScheduled = false
    func checkDone(_ peripheral: CBPeripheral) {
        // Give a short grace period after the last read to flush the tree, then exit.
        guard !doneScheduled else { return }
        DispatchQueue.main.asyncAfter(deadline: .now() + 3) { [weak self] in
            guard let self else { return }
            if self.pendingReads == 0 {
                self.doneScheduled = true
                self.log("\n[ble] GATT dump complete (read-only). Disconnecting.")
                self.central.cancelPeripheralConnection(peripheral)
                DispatchQueue.main.asyncAfter(deadline: .now() + 1) { exit(0) }
            }
        }
    }
}

let (mode, scanSeconds) = parseArgs()

// Self-test: validate AES-128-ECB against the FIPS-197 known-answer vector BEFORE
// trusting it on real hardware. No Bluetooth involved.
if case .selftest = mode {
    // FIPS-197 Appendix B / C.1: key 000102…0f, plaintext 00112233…ff →
    // ciphertext 69c4e0d86a7b0430d8cdb78070b4c55a
    let key = Data((0...15).map { UInt8($0) })
    let pt  = Data([0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff])
    let expected = "69c4e0d86a7b0430d8cdb78070b4c55a"
    guard let ct = OuraProtocol.aes128ECBEncrypt(key: key, block16: pt) else {
        print("[selftest] ❌ AES returned nil"); exit(1)
    }
    let got = ct.map { String(format: "%02x", $0) }.joined()
    print("[selftest] AES-128-ECB(0x000102…0f, 0x00112233…ff)")
    print("[selftest]   expected = \(expected)")
    print("[selftest]   got      = \(got)")
    if got == expected {
        print("[selftest] ✅ AES-128-ECB is correct. Proof computation can be trusted.")
        // Also demo the proof builder with a sample 15-byte nonce (sanity, not a KAT).
        let nonce = Data((1...15).map { UInt8($0) })
        let demoKey = OuraProtocol.randomAuthKey()
        if let proof = OuraProtocol.computeProof(authKey: demoKey, nonce15: nonce) {
            print("[selftest]   demo proof len = \(proof.count) (expect 16)")
        }
        exit(0)
    } else {
        print("[selftest] ❌ MISMATCH — do NOT use this for takeover."); exit(1)
    }
}

let explorer = Explorer(mode: mode, scanSeconds: scanSeconds)

// Overall safety timeout so the process never hangs forever.
DispatchQueue.main.asyncAfter(deadline: .now() + max(scanSeconds + 40, 60)) {
    FileHandle.standardError.write(Data("[ble] Global timeout reached; exiting.\n".utf8))
    exit(0)
}

RunLoop.main.run()
