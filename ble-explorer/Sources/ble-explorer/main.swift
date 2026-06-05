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
//   swift run ble-explorer --read [hexkey] [--history] [--seconds N]
//                                          # auth (Keychain key) → read battery/firmware/
//                                          #   product, then stream live TLV records for N s.
//                                          # --history also fetches buffered flash history.
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
// History cursor spec from `--cursor` (nil = full dump from 0). Read by the read
// sequence; a global keeps it out of the already-wide Mode enum.
var historyCursorSpec: String? = nil

// `--drain`: throughout the stream window, repeatedly GetEvent from the latest seen
// ringTimestamp to pull records (esp. raw PPG 0x81) as the worn ring generates them,
// instead of a single start-of-session fetch.
var drainMode = false

// `--burst`: keep the DHR (feature 0x02) "burst" HR mode engaged. open_ring §6.7:
// the ring auto-reverts to mode 0 after ~20 s, so the app re-triggers every ~15 s.
// We re-send `set 0x02=0x03` + `subscribe 0x02=0x02` every ~12 s to keep the raw
// PPG (0x81) burst flowing, and GetEvent-drain it.
var burstMode = false

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
    case auth(key: Data)  // reconnect → GetAuthNonce → Authenticate with our saved key
    case reset(key: Data) // authenticate with our key, then ResetMemory (give the ring back)
    case read(key: Data, seconds: Double, history: Bool, features: [UInt8]) // auth → read infos → subscribe → stream
    case storeKey(key: Data) // migrate a key into the macOS Keychain, no BLE
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
    var wantRead = false       // deferred: --read may appear before/after --seconds/--history
    var readKey: Data? = nil
    var readHistory = false
    var readSeconds = 20.0
    var readFeatures: [UInt8] = [0x02]   // default: the AFE feature we know streams
    let args = Array(CommandLine.arguments.dropFirst())
    var i = 0
    while i < args.count {
        switch args[i] {
        case "--oura":
            mode = .ouraOnly
        case "--read":
            // Key from arg, else from Keychain. Resolved into a mode after the loop
            // so --seconds / --history can appear in any order.
            wantRead = true
            if i + 1 < args.count, let k = hexToData(args[i + 1]) {
                readKey = k; i += 1
            } else {
                readKey = Keychain.loadAuthKey()
            }
        case "--history":
            readHistory = true
        case "--cursor":
            // "0" (default), "recent" (ring-now minus a window), or an explicit hex.
            if i + 1 < args.count {
                historyCursorSpec = args[i + 1]; readHistory = true; i += 1
            }
        case "--drain":
            // Repeatedly GetEvent at the advancing cursor during the stream window.
            drainMode = true; readHistory = true
            if historyCursorSpec == nil { historyCursorSpec = "recent" }
        case "--burst":
            // Keep DHR burst HR mode engaged + drain, to capture raw PPG (0x81).
            burstMode = true; drainMode = true; readHistory = true
            if historyCursorSpec == nil { historyCursorSpec = "recent" }
        case "--features":
            // Comma/space-separated hex feature IDs to subscribe, e.g. "02,03,0b".
            if i + 1 < args.count {
                let parsed = args[i + 1]
                    .split(whereSeparator: { $0 == "," || $0 == " " })
                    .compactMap { UInt8($0.replacingOccurrences(of: "0x", with: ""), radix: 16) }
                if !parsed.isEmpty { readFeatures = parsed }
                i += 1
            }
        case "--takeover":
            mode = .takeover
        case "--auth":
            // Key from arg, else from Keychain.
            if i + 1 < args.count, let k = hexToData(args[i + 1]) {
                mode = .auth(key: k); i += 1
            } else if let k = Keychain.loadAuthKey() {
                mode = .auth(key: k)
            } else {
                FileHandle.standardError.write(Data("--auth: provide a 32-hex key or store one first (--store-key)\n".utf8))
                exit(2)
            }
        case "--reset":
            if i + 1 < args.count, let k = hexToData(args[i + 1]) {
                mode = .reset(key: k); i += 1
            } else if let k = Keychain.loadAuthKey() {
                mode = .reset(key: k)
            } else {
                FileHandle.standardError.write(Data("--reset: provide a 32-hex key or store one first (--store-key)\n".utf8))
                exit(2)
            }
        case "--store-key":
            if i + 1 < args.count, let k = hexToData(args[i + 1]) {
                mode = .storeKey(key: k); i += 1
            } else {
                FileHandle.standardError.write(Data("--store-key requires a 32-hex-char (16-byte) key\n".utf8))
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
                scanSeconds = s; readSeconds = s; i += 1
            }
        default:
            FileHandle.standardError.write(Data("Unknown arg: \(args[i])\n".utf8))
        }
        i += 1
    }
    if wantRead {
        guard let k = readKey else {
            FileHandle.standardError.write(Data("--read: provide a 32-hex key or store one first (--store-key)\n".utf8))
            exit(2)
        }
        mode = .read(key: k, seconds: readSeconds, history: readHistory, features: readFeatures)
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

    // Read state
    var readPhase = false          // true once auth succeeds in read mode → route notifies to read handler
    var streamLeftover = Data()    // bytes from a previous notify that didn't frame a full record
    var recordCounts: [UInt8: Int] = [:]  // per-type tally for the end-of-run summary
    var streamSampleCount = 0      // live feature-data samples (2f/0x28) seen this run
    var ringNowTimestamp: UInt32 = 0  // ring's current ringTimestamp, from the SyncTime ack
    var allIBIms: [Int] = []          // clean beat intervals (0x80/0x60) across the run
    var latestSeenTs: UInt32 = 0      // highest ringTimestamp seen (for --drain cursor)
    var readStreamSeconds: Double { if case .read(_, let s, _, _) = mode { return s } else { return 20 } }
    var readWantsHistory: Bool { if case .read(_, _, let h, _) = mode { return h } else { return false } }
    var readFeatureIDs: [UInt8] { if case .read(_, _, _, let f) = mode { return f } else { return [0x02] } }

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
        case .ouraOnly, .takeover, .auth, .reset, .read:
            if case .takeover = mode {
                log("[takeover] ⚠️ This will SET OUR OWN auth_key on the ring. Only run on a FACTORY-RESET ring.")
                log("[takeover] Put the ring in PAIRING MODE: remove from charger and put it back (white blinking light).")
            }
            if case .auth = mode {
                log("[auth] Persistence test: reconnect → authenticate with our saved key.")
            }
            if case .reset = mode {
                log("[reset] ⚠️ This will AUTHENTICATE then FACTORY-RESET the ring (give it back). Data on the ring is erased.")
            }
            if case .read = mode {
                log("[read] Reconnect → authenticate → read battery/firmware/product, then stream live records.")
                log("[read] ⚠️ For physiological data (PPG/IBI/temp/accel) the ring must be WORN, not on the charger.")
            }
            log("[ble] Scanning for Oura service \(ouraServiceUUID.uuidString)…")
            central.scanForPeripherals(withServices: [ouraServiceUUID], options: nil)
            DispatchQueue.main.asyncAfter(deadline: .now() + 4) { [weak self] in
                guard let self, self.target == nil else { return }
                self.log("[ble] No Oura-service advert yet; widening to a full scan…")
                self.central.stopScan()
                self.central.scanForPeripherals(withServices: nil, options: nil)
            }
        case .selftest, .storeKey:
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
        case .ouraOnly, .takeover, .auth, .reset, .read:
            let advertisesOura = (advertisementData[CBAdvertisementDataServiceUUIDsKey] as? [CBUUID])?.contains(ouraServiceUUID) ?? false
            if advertisesOura || advName.lowercased().contains("oura") {
                log("[ble] Found candidate Oura device: \(advName) [\(peripheral.identifier.uuidString)] rssi=\(RSSI.intValue) connectable=\(connStr)")
                central.stopScan()
                connect(peripheral)
            }
        case .selftest, .storeKey:
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
    var isReset: Bool { if case .reset = mode { return true } else { return false } }
    var isRead: Bool { if case .read = mode { return true } else { return false } }
    var isHandshake: Bool { isTakeover || isAuthOnly || isReset || isRead }
    var handshakeTag: String { isTakeover ? "takeover" : (isReset ? "reset" : (isRead ? "read" : "auth")) }

    func peripheral(_ peripheral: CBPeripheral, didUpdateNotificationStateFor characteristic: CBCharacteristic, error: Error?) {
        guard isHandshake, characteristic == notifyChar else { return }
        let tag = isTakeover ? "takeover" : "auth"
        if let error { log("[\(tag)] Failed to enable notifications: \(error.localizedDescription)"); exit(1) }
        guard takeoverStep == .idle else { return }
        takeoverStep = .notifyEnabled

        // auth, reset & read: authenticate first with the saved key (skip SetAuthKey).
        var savedKey: Data? = nil
        if case .auth(let k) = mode { savedKey = k }
        if case .reset(let k) = mode { savedKey = k }
        if case .read(let k, _, _, _) = mode { savedKey = k }
        if let key = savedKey {
            myAuthKey = key
            log("[\(tag)] Notifications enabled. Authenticating with saved key \(hex(myAuthKey))")
            log("[\(tag)] → GetAuthNonce (2F 01 2B)…")
            takeoverStep = .sentNonce
            write(OuraProtocol.getAuthNonce())
        } else {
            log("[takeover] Notifications enabled. My auth_key = \(hex(myAuthKey))")
            log("[takeover] → SetAuthKey (0x24)…")
            takeoverStep = .sentSetAuthKey
            write(OuraProtocol.setAuthKey(myAuthKey))
        }
    }

    func write(_ data: Data, label: String? = nil) {
        guard let wc = writeChar, let p = target else { return }
        log("[\(label ?? handshakeTag)]   write: \(hex(data))")
        // Use withResponse if supported, else withoutResponse.
        let type: CBCharacteristicWriteType = wc.properties.contains(.write) ? .withResponse : .withoutResponse
        p.writeValue(data, for: wc, type: type)
    }

    func peripheral(_ peripheral: CBPeripheral, didUpdateValueFor characteristic: CBCharacteristic, error: Error?) {
        // Read mode, post-auth: every notify is an info-response or a stream record.
        if readPhase, characteristic == notifyChar {
            guard let data = characteristic.value else { return }
            handleReadNotification(data, peripheral: peripheral)
            return
        }
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
                log("[\(handshakeTag)] ❌ Unexpected nonce length \(nonce.count) (expected 15). Stopping."); finishTakeover(peripheral, success: false); return
            }
            guard let proof = OuraProtocol.computeProof(authKey: myAuthKey, nonce15: nonce) else {
                log("[\(handshakeTag)] ❌ Proof computation failed."); finishTakeover(peripheral, success: false); return
            }
            log("[\(handshakeTag)] nonce=\(hex(nonce)) → proof=\(hex(proof)). → Authenticate…")
            takeoverStep = .sentAuth
            write(OuraProtocol.authenticate(proof: proof))
        case "auth":
            let code = parsed.payload.first ?? 0xFF
            if code == 0x00 {
                log("[\(handshakeTag)] 🎉 AUTHENTICATED with OUR key (code=0x00).")
                if isRead {
                    startReadSequence(peripheral)
                } else if isReset {
                    // Now give the ring back: ResetMemory.
                    log("[reset] → ResetMemory (factory reset, [0x1A 0x00])…")
                    takeoverStep = .done   // reuse; we wait for the reset response below via a fresh step guard
                    resetSent = true
                    write(Data([OuraOpcode.resetMemory, 0x00]))   // matches the app's ResetMemory(false)
                    // Some firmwares reset without replying; exit after a short grace.
                    DispatchQueue.main.asyncAfter(deadline: .now() + 4) { [weak self] in
                        guard let self else { return }
                        self.log("[reset] ✅ ResetMemory sent. Ring should now be factory-reset (leave it still ~2 min).")
                        self.central.cancelPeripheralConnection(peripheral)
                        DispatchQueue.main.asyncAfter(deadline: .now() + 1) { exit(0) }
                    }
                } else {
                    finishTakeover(peripheral, success: true)
                }
            } else {
                let meaning = ["0x01":"auth error", "0x02":"in factory reset", "0x03":"not original onboarded device"]["0x\(String(format: "%02x", code))"] ?? "unknown"
                log("[\(handshakeTag)] ❌ Authenticate failed (code=0x\(String(format: "%02x", code)) = \(meaning)).")
                finishTakeover(peripheral, success: false)
            }
        case "raw":
            // In reset mode, a 1b… response is the ResetMemory ack.
            if isReset, resetSent, parsed.payload.first == 0x1B {
                log("[reset] ✅ ResetMemory acknowledged: \(hex(parsed.payload))")
            }
        default:
            break
        }
    }
    var resetSent = false

    // MARK: - Read sequence (post-auth)

    /// After auth succeeds, replay the app's post-auth init then query device info,
    /// then open the live stream. All raw responses are logged + TLV-decoded so we
    /// can validate formats against the real ring (observation-first, no guessing).
    func startReadSequence(_ peripheral: CBPeripheral) {
        guard !readPhase else { return }
        readPhase = true
        takeoverStep = .done   // stop the handshake state machine from re-entering
        log("\n[read] ✅ Authenticated. Beginning read sequence.")

        // 1) Post-auth init, mirroring the captured Android onboarding order:
        //    SetBleMode(0x02) → SyncTime(now) → SetNotification(0xbf).
        // SyncTime uses the current unix time so the ring anchors its tick counter.
        let now = UInt32(Date().timeIntervalSince1970)
        write(OuraProtocol.setBleMode(0x02), label: "read")
        delay(0.4) { self.write(OuraProtocol.syncTime(unix: now), label: "read") }
        delay(0.8) { self.write(OuraProtocol.setNotification(0xbf), label: "read") }

        // 2) Device info queries (simple, short responses — our first real reads).
        delay(1.3) {
            self.log("[read] → GetFirmwareVersion (0x08)…")
            self.write(OuraProtocol.getFirmwareVersion(), label: "read")
        }
        delay(1.8) {
            self.log("[read] → GetBatteryLevel (0x0C)…")
            self.write(OuraProtocol.getBatteryLevel(), label: "read")
        }
        // Product-info sub-queries observed in the capture (14/18/28/34/04/08).
        let subs: [UInt8] = [0x14, 0x18, 0x28, 0x34, 0x04, 0x08]
        for (n, sub) in subs.enumerated() {
            delay(2.3 + Double(n) * 0.4) {
                self.log("[read] → GetProductInfo sub=0x\(String(format: "%02x", sub)) (0x18)…")
                self.write(OuraProtocol.getProductInfo(sub: sub), label: "read")
            }
        }

        // 3) Feature subscribe block — replays the app's get/set/subscribe sequence
        //    decoded from the capture (frames 926-992). For each requested feature:
        //    get → set=0x03 → SUBSCRIBE=0x02. Feature 0x02 is the AFE channel we
        //    confirmed streams on a worn ring; `--features` overrides the list so we
        //    can probe others (0x03/0x04/0x0b/0x0d/0x10 seen in the capture) for the
        //    raw PPG waveform / IBI channel.
        let subStart = 2.3 + Double(subs.count) * 0.4 + 0.5
        let feats = readFeatureIDs
        delay(subStart) {
            self.log("\n[read] → feature subscribe for IDs [\(feats.map { String(format: "0x%02x", $0) }.joined(separator: ", "))]…")
        }
        for (n, fid) in feats.enumerated() {
            let base = subStart + Double(n) * 0.9
            delay(base)       { self.write(OuraProtocol.featureGet(fid), label: "read") }
            delay(base + 0.3) { self.write(OuraProtocol.featureSet(fid, 0x03), label: "read") }
            delay(base + 0.6) { self.write(OuraProtocol.featureSubscribe(fid, 0x02), label: "read") }
        }

        // 4) Open the data plane. data_flush (0x28) releases buffered events onto the
        //    BLE notify stream; combined with the subscribe above, new measurement
        //    records should follow while the ring is worn.
        let afterInfo = subStart + Double(feats.count) * 0.9 + 0.5
        delay(afterInfo) {
            self.log("\n[read] → data_flush (0x28) — release buffered events to the stream…")
            self.write(OuraProtocol.dataFlush(), label: "read")
        }

        // Optional explicit history dump. Cursor strategy (learned from the capture:
        // the app's biosignal records arrived via GetEvent with a RECENT cursor, not
        // cursor 0 which only replays the old boot/charge log):
        //  - default: cursor 0 (full dump)
        //  - `--cursor recent`: use the ring's current ringTimestamp (from SyncTime
        //    ack) minus a window, so we fetch only the most recent records.
        //  - `--cursor <hex>`: explicit cursor.
        if readWantsHistory {
            delay(afterInfo + 0.5) {
                let cur = self.resolveHistoryCursor()
                self.log("[read] → GetEvent (0x10) history fetch from cursor 0x\(String(format: "%08x", cur))…")
                self.write(OuraProtocol.getEvent(cursor: cur), label: "read")
            }
        }

        let streamStart = afterInfo + (readWantsHistory ? 1.0 : 0.4)
        delay(streamStart) {
            self.log("\n[read] === LIVE STREAM open for \(Int(self.readStreamSeconds))s — wear the ring, keep still for clean PPG/IBI ===")
        }

        // --burst: re-engage the DHR burst HR mode every ~12 s (ring auto-reverts to
        // mode 0 after ~20 s). This is what makes the ring emit the raw PPG (0x81).
        if burstMode {
            var t = streamStart + 0.2
            while t < streamStart + readStreamSeconds {
                delay(t) {
                    self.log("[read] → DHR burst re-trigger (set 0x02=0x03, subscribe 0x02=0x02)…")
                    self.write(OuraProtocol.featureSet(0x02, 0x03), label: "read")
                }
                delay(t + 0.3) { self.write(OuraProtocol.featureSubscribe(0x02, 0x02), label: "read") }
                t += 12.0
            }
        }

        // --drain: every ~2.5 s, re-issue GetEvent from the latest ringTimestamp seen,
        // to pull records (esp. raw PPG 0x81) as the worn ring generates them.
        if drainMode {
            let every = 2.5
            var t = streamStart + 1.0
            while t < streamStart + readStreamSeconds {
                delay(t) {
                    let cur = self.latestSeenTs > 0 ? self.latestSeenTs + 1 : self.resolveHistoryCursor()
                    self.log("[read] → drain GetEvent from cursor 0x\(String(format: "%08x", cur))…")
                    self.write(OuraProtocol.getEvent(cursor: cur), label: "read")
                }
                t += every
            }
        }

        // Close the stream window and summarize.
        delay(streamStart + readStreamSeconds) {
            self.finishRead(peripheral)
        }
    }

    /// Decide which ringTimestamp cursor to pass to GetEvent, from `--cursor`:
    ///  - nil / "0"  → 0 (full dump)
    ///  - "recent"   → ring's current ringTimestamp minus a window (recent records)
    ///  - "<hex>"    → that explicit value
    func resolveHistoryCursor() -> UInt32 {
        guard let spec = historyCursorSpec else { return 0 }
        if spec == "recent" {
            // Window back from "now" so we catch recent measurement records but not
            // the whole boot/charge log. 0x2000 counter-ticks ≈ a few minutes.
            let window: UInt32 = 0x2000
            return ringNowTimestamp > window ? ringNowTimestamp - window : 0
        }
        if let v = UInt32(spec.replacingOccurrences(of: "0x", with: ""), radix: 16) { return v }
        return 0
    }

    /// Schedule a closure on the main queue after `s` seconds (thin wrapper for
    /// readability of the staged read sequence above).
    func delay(_ s: Double, _ body: @escaping () -> Void) {
        DispatchQueue.main.asyncAfter(deadline: .now() + s, execute: body)
    }

    /// Handle a notify in the post-auth read phase: classify info-responses vs
    /// stream records. Info responses use the request-opcode+1 reply tags seen in
    /// the capture (0x18→0x19 etc.); everything else we attempt to TLV-decode.
    func handleReadNotification(_ data: Data, peripheral: CBPeripheral) {
        guard let tag = data.first else { return }
        let body = data.count > 2 ? Data(data.dropFirst(2)) : Data()  // skip [tag][len]

        switch tag {
        case 0x09:   // GetFirmwareVersion response
            log("[read] ⟵ firmware: hex=[\(hex(data))] ascii=\"\(ascii(data))\"")
        case 0x0D:   // GetBatteryLevel response (0x0C + 1)
            let pct = body.first.map { Int($0) }
            log("[read] ⟵ battery: \(pct.map { "\($0)%" } ?? "?")  raw=[\(hex(data))]")
        case 0x19:   // GetProductInfo response — ASCII identity strings
            log("[read] ⟵ product: hex=[\(hex(data))] ascii=\"\(ascii(data))\"")
        case 0x11:   // GetEvent response (history) — body is a TLV record buffer
            log("[read] ⟵ history chunk: \(data.count)B")
            ingestRecords(body, source: "history")
        case 0x2F:   // extended responses: feature get(0x21)/set(0x23)/subscribe(0x27)
            // Layout: 2f <len> <sub> <id> <value…>
            let b = [UInt8](data)
            if b.count >= 4, b[2] == 0x28 {
                // Live feature DATA stream (sub 0x28). Verified on worn ring:
                //   2f 0f 28 <feat> <chan:1> 02 00 00 <value u16 LE> 00 00 00 00 <suffix:3>
                // chan ∈ {0x09,0x19}; value oscillates ~PPG/AFE counts. (Sample rate
                // here was ~0.5 Hz → likely an AFE stat/quality channel, not the raw
                // high-rate PPG waveform — flagged for further investigation.)
                let feat = b[3]
                if b.count >= 10 {
                    let chan = b[4]
                    let value = UInt16(b[8]) | (UInt16(b[9]) << 8)
                    streamSampleCount += 1
                    log("[read] ⟵ live feat=0x\(String(format: "%02x", feat)) chan=0x\(String(format: "%02x", chan)) value=\(value)  raw=[\(hex(data))]")
                } else {
                    log("[read] ⟵ live feat=0x\(String(format: "%02x", feat)) (short) raw=[\(hex(data))]")
                }
            } else if b.count >= 4 {
                let sub = b[2], id = b[3]
                let val = b.count > 4 ? hex(Data(b[4...])) : ""
                let kind = ["0x21": "feature-value", "0x23": "set-ack", "0x27": "SUBSCRIBE-ack"]["0x\(String(format: "%02x", sub))"] ?? "ext-0x\(String(format: "%02x", sub))"
                log("[read] ⟵ \(kind) feature=0x\(String(format: "%02x", id)) value=[\(val)]  raw=[\(hex(data))]")
            } else {
                log("[read] ⟵ ext: hex=[\(hex(data))]")
            }
        case 0x1F:   // ext ack (short form) — log raw
            log("[read] ⟵ ext: hex=[\(hex(data))]")
        case 0x17:   // SetBleMode ack
            log("[read] ⟵ ack SetBleMode: [\(hex(data))]")
        case 0x13:   // SyncTime ack — body carries the ring's current ringTimestamp
            let rt = body.count >= 4 ? UInt32(body[0]) | (UInt32(body[1])<<8) | (UInt32(body[2])<<16) | (UInt32(body[3])<<24) : 0
            ringNowTimestamp = rt
            log("[read] ⟵ ack SyncTime: ringTimestamp=0x\(String(format: "%08x", rt)) raw=[\(hex(data))]")
        case 0x1D:   // SetNotification ack
            log("[read] ⟵ ack SetNotification: [\(hex(data))]")
        case 0x29:   // data_flush ack
            log("[read] ⟵ ack data_flush: [\(hex(data))]")
        default:
            // Unsolicited stream notification: treat the whole value as TLV records.
            // (Some firmwares prefix a frame header; if framing fails we log raw.)
            let before = recordCounts.values.reduce(0, +)
            ingestRecords(data, source: "stream")
            let after = recordCounts.values.reduce(0, +)
            if after == before {
                log("[read] ⟵ raw (undecoded): hex=[\(hex(data))] ascii=\"\(ascii(data))\"")
            }
        }
    }

    /// Append a notify buffer to the rolling stream buffer, decode whole TLV records,
    /// log each, and keep any partial trailing bytes for the next notification.
    func ingestRecords(_ data: Data, source: String) {
        streamLeftover.append(data)
        let (records, leftover) = OuraProtocol.decodeRecords(streamLeftover)
        streamLeftover = leftover
        for r in records {
            recordCounts[r.type, default: 0] += 1
            if r.ringTimestamp > latestSeenTs { latestSeenTs = r.ringTimestamp }
            let name = OuraProtocol.recordTypeName(r.type)
            // Type-specific human decode, validated against our own dump:
            //  0x43 = ASCII diagnostic log line; 0x42 = time anchor (unix ts LE).
            var extra = ""
            if r.type == 0x43 {
                extra = "  \"\(ascii(r.payload))\""
            } else if r.type == 0x42, r.payload.count >= 4 {
                let p = [UInt8](r.payload)
                let unix = UInt32(p[0]) | (UInt32(p[1])<<8) | (UInt32(p[2])<<16) | (UInt32(p[3])<<24)
                let date = Date(timeIntervalSince1970: TimeInterval(unix))
                extra = "  unixAnchor=\(unix) (\(date))"
            } else if let bio = OuraProtocol.decodeBiosignal(r) {
                extra = "  \(bio)"
                allIBIms.append(contentsOf: OuraProtocol.ibiValues(r))
            }
            log(String(format: "[%@] type=0x%02x %-12@ ts=%u ses=%u ctr=%u payload(%d)=[%@]%@",
                       source, r.type, name as NSString, r.ringTimestamp, r.session, r.counter,
                       r.payload.count, hex(r.payload), extra))
        }
    }

    func finishRead(_ peripheral: CBPeripheral) {
        log("\n[read] === Stream window closed. Record summary ===")
        if streamSampleCount > 0 {
            log("[read]   live feature-data samples (2f/0x28): \(streamSampleCount)")
        }
        if recordCounts.isEmpty {
            if streamSampleCount == 0 {
                log("[read] (no records decoded — if the ring was on the charger, wear it and re-run.)")
            }
        } else {
            for (t, c) in recordCounts.sorted(by: { $0.key < $1.key }) {
                log("[read]   type=0x\(String(format: "%02x", t)) \(OuraProtocol.recordTypeName(t)): \(c)")
            }
        }
        if !streamLeftover.isEmpty {
            log("[read]   unframed trailing bytes: [\(hex(streamLeftover))]")
        }
        // Aggregate heart rate / HRV from all clean IBI beats this run.
        if allIBIms.count >= 3 {
            let n = Double(allIBIms.count)
            let mean = Double(allIBIms.reduce(0, +)) / n
            let bpm = 60000.0 / mean
            // RMSSD: root-mean-square of successive IBI differences — the standard
            // short-term HRV metric.
            var sq = 0.0
            for k in 1..<allIBIms.count {
                let d = Double(allIBIms[k] - allIBIms[k-1]); sq += d * d
            }
            let rmssd = (allIBIms.count > 1) ? (sq / Double(allIBIms.count - 1)).squareRoot() : 0
            log(String(format: "\n[read] ❤️  HEART RATE: %.0f bpm  (mean IBI %.0f ms over %d beats)  HRV(RMSSD)=%.0f ms",
                       bpm, mean, allIBIms.count, rmssd))
        }
        central.cancelPeripheralConnection(peripheral)
        delay(1) { exit(0) }
    }

    func finishTakeover(_ peripheral: CBPeripheral, success: Bool) {
        guard takeoverStep != .done else { return }
        takeoverStep = .done
        if success {
            if isAuthOnly {
                log("\n[auth] ✅ PERSISTENCE CONFIRMED — the ring remembered our key. We can re-authenticate anytime.")
            } else if isTakeover {
                let hexKey = hex(myAuthKey).replacingOccurrences(of: " ", with: "")
                if Keychain.storeAuthKey(myAuthKey) {
                    log("\n[takeover] ✅ SUCCESS. Key stored in macOS Keychain. (also shown below)")
                } else {
                    log("\n[takeover] ✅ SUCCESS (⚠️ failed to store in Keychain — save it manually).")
                }
                log("[takeover]   AUTH_KEY=\(hexKey)")
            }
        } else {
            log("\n[\(handshakeTag)] ✗ Did not complete. See messages above.")
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

// Store-key: migrate the auth key into the macOS Keychain (no BLE).
if case .storeKey(let key) = mode {
    if Keychain.storeAuthKey(key) {
        print("[keychain] ✅ auth_key stored in macOS Keychain (service=\(Keychain.service)).")
        print("[keychain] You can now run --auth / --reset without passing the key.")
        print("[keychain] Reminder: also delete the plaintext secrets/ring-auth-key.txt if you want.")
        exit(0)
    } else {
        print("[keychain] ❌ Failed to store key."); exit(1)
    }
}

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

// Overall safety timeout so the process never hangs forever. In read mode the
// stream window itself is `seconds` long, so budget generously around it
// (scan + connect + ~6s init + stream + grace).
var safetyTimeout = max(scanSeconds + 40, 60)
if case .read(_, let s, _, _) = mode { safetyTimeout = max(safetyTimeout, s + 60) }
DispatchQueue.main.asyncAfter(deadline: .now() + safetyTimeout) {
    FileHandle.standardError.write(Data("[ble] Global timeout reached; exiting.\n".utf8))
    exit(0)
}

RunLoop.main.run()
