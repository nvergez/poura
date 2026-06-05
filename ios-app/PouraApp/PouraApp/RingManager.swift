// RingManager — the iOS CoreBluetooth driver for the Oura Ring 4.
//
// This is the iOS port of the macOS `ble-explorer` tool's BLE state machine
// (Sources/ble-explorer/main.swift). The protocol layer itself lives in PouraCore
// (OuraProtocol) and is shared verbatim; this file only owns the CoreBluetooth
// plumbing and surfaces state to SwiftUI via @Published properties instead of print.
//
// Faithfully reproduces the VERIFIED sequences from main.swift:
//   takeover : connect → notify on → SetAuthKey(ours) → GetAuthNonce → Authenticate
//   auth     : connect → notify on → GetAuthNonce → Authenticate(saved key)
//   read     : auth → SetBleMode/SyncTime/SetNotification → info queries →
//              feature get/set/subscribe(0x02) → data_flush → [GetEvent] → stream
//
// Key iOS difference vs macOS, surfaced in the UI: this is a SEPARATE BLE central
// from the Mac. It does NOT inherit the Mac's bond or Keychain. The ring trusts an
// auth_key, not a phone — so either (a) import the same 16-byte key the Mac uses, or
// (b) factory-reset the ring and take it over fresh from this device.

import Foundation
import CoreBluetooth
import PouraCore

// GATT identifiers — CONFIRMED against the real ring (see docs/PROTOCOL.md).
private let ouraServiceUUID = CBUUID(string: "98ed0001-a541-11e4-b6a0-0002a5d5c51b")
private let ouraWriteCharUUID = CBUUID(string: "98ed0002-a541-11e4-b6a0-0002a5d5c51b")
private let ouraNotifyCharUUID = CBUUID(string: "98ed0003-a541-11e4-b6a0-0002a5d5c51b")

/// What the user asked the manager to do this session.
enum RingOperation: Equatable {
    case takeover               // set OUR key on a factory-reset ring (pairing mode)
    case authenticate(Data)     // re-auth with a saved 16-byte key
    case read(Data)             // auth then run the read sequence (worn ring)
    case factoryReset(Data)     // auth with our key, then ResetMemory (give the ring back)
}

/// Coarse lifecycle state for the UI to switch on.
enum RingPhase: Equatable {
    case idle
    case bluetoothUnavailable(String)
    case scanning
    case connecting
    case discovering
    case authenticating
    case reading
    case done(success: Bool, message: String)
}

/// A decoded line for the live log view (kept structured so the UI can style it).
struct LogLine: Identifiable {
    let id = UUID()
    let text: String
    let kind: Kind
    enum Kind { case info, tx, rx, biosignal, success, error }
}

/// One heart-rate / HRV summary computed from the run's clean IBI beats.
struct VitalsSummary: Equatable {
    var bpm: Int
    var meanIBIms: Int
    var beats: Int
    var rmssdMs: Int
}

/// Read-session diagnostics. Surfaces the cursor machinery so we can distinguish
/// "ring has no biosignals yet" from "our fetch is replaying the old log".
struct ReadDiagnostics: Equatable {
    var ringNowTs: UInt32 = 0          // ring's current ringTimestamp (from SyncTime ack)
    var syncAckSeen = false            // did the 0x13 ack actually arrive?
    var lastCursor: UInt32 = 0         // cursor of the most recent GetEvent we sent
    var getEventCount = 0              // how many GetEvent requests we've issued
    var latestRecordTs: UInt32 = 0     // highest ringTimestamp seen in returned records
    var bioRecordCount = 0             // count of biosignal-type records (0x46/0x80/…)
    var afeSamples = 0                 // live AFE stream samples (feature 0x02)

    /// How far the newest logged record trails the ring's live clock, in ticks. A small
    /// gap = the flash log is current (records were written recently). A large gap = the
    /// ring stopped logging a while ago (idle / no measurement session).
    var recordLagTicks: Int { ringNowTs > latestRecordTs ? Int(ringNowTs - latestRecordTs) : 0 }

    /// The log is "fresh" if the newest record is within a few thousand ticks of now.
    /// (Tuned loosely — the point is to flag a stale log, not a precise threshold.)
    var logIsFresh: Bool { latestRecordTs > 0 && recordLagTicks < 0x800 }
}

/// Granular progress for the onboarding (pairing) wizard. Drives the step UI; the
/// underlying BLE work is the same `.takeover` operation, but onboarding wants to
/// show each stage and interpret failures in plain language.
enum OnboardingStep: Equatable {
    case notStarted
    case scanning                 // looking for a ring in pairing mode
    case connecting               // found it, bonding (Just Works)
    case claiming                 // SetAuthKey(our new key) → nonce → Authenticate
    case succeeded(keyHex: String)
    case failed(OnboardingFailure)
}

/// Why onboarding stopped, in terms the UI can explain + recover from.
enum OnboardingFailure: Equatable {
    case bluetoothUnavailable(String)
    case ringAlreadyClaimed       // auth 0x03 / SetAuthKey rejected — needs a factory reset
    case ringInFactoryReset       // auth 0x02 — ring still resetting, retry shortly
    case staleBond                // "peer removed pairing information"
    case generic(String)

    var title: String {
        switch self {
        case .bluetoothUnavailable: return "Bluetooth unavailable"
        case .ringAlreadyClaimed:   return "Ring is already claimed"
        case .ringInFactoryReset:   return "Ring is still resetting"
        case .staleBond:            return "Stale Bluetooth bond"
        case .generic:              return "Pairing failed"
        }
    }

    var detail: String {
        switch self {
        case .bluetoothUnavailable(let m): return m
        case .ringAlreadyClaimed:
            return "This ring is still bound to another app/key. Factory-reset it first: put it on a powered charger and tap the charger on a hard surface ~5–10×, then try again."
        case .ringInFactoryReset:
            return "The ring reports it's mid factory-reset. Leave it still ~30s and retry."
        case .staleBond:
            return "Your phone cached an old pairing. Open Settings → Bluetooth, forget the ring if listed, then retry."
        case .generic(let m): return m
        }
    }
}

@MainActor
final class RingManager: NSObject, ObservableObject {

    // MARK: Published UI state
    @Published private(set) var phase: RingPhase = .idle
    @Published private(set) var log: [LogLine] = []
    @Published private(set) var battery: Int?
    @Published private(set) var firmware: String?
    @Published private(set) var product: String?
    @Published private(set) var recordCounts: [UInt8: Int] = [:]
    @Published private(set) var vitals: VitalsSummary?
    @Published private(set) var liveSamples = 0

    /// Onboarding wizard progress. Only meaningful while an onboarding run is active.
    @Published private(set) var onboardingStep: OnboardingStep = .notStarted

    /// Live diagnostics for a read — lets us SEE whether the GetEvent cursor is reaching
    /// fresh measurement records or replaying the old charge/boot log.
    @Published private(set) var diag = ReadDiagnostics()

    /// Flips true once a factory-reset op completes successfully. The main view watches
    /// this to delete the now-defunct local key and return to onboarding. The UI must
    /// call `acknowledgeFactoryReset()` after handling it so it doesn't re-fire.
    @Published private(set) var factoryResetSucceeded = false

    /// True if a 16-byte key is already stored — the app skips onboarding when so.
    var hasSavedKey: Bool { Keychain.loadAuthKey()?.count == 16 }

    /// How long to hold the read window open (seconds). Longer = more DHR burst cycles
    /// (one every ~12s), so more chance the ring logs heart-rate data.
    var streamSeconds: Double = 45
    /// Also fetch buffered history via GetEvent (`--cursor recent`) at session start.
    var fetchRecentHistory = true
    /// Mirror the CLI's `--drain`: repeatedly GetEvent from the advancing cursor over
    /// the window, pulling fresh biosignal records as the worn ring generates them —
    /// instead of a single start-of-session fetch (which can land in the old log).
    var drainMode = true
    /// Mirror the CLI's `--burst`: actively re-engage DHR HR mode (feature 0x02) every
    /// ~12s so the ring measures + logs IBI/temp, instead of passively waiting for a
    /// scheduled measurement session that may never come while idle-connected.
    var burstMode = true

    // MARK: BLE
    private var central: CBCentralManager!
    private var ring: CBPeripheral?
    private var writeChar: CBCharacteristic?
    private var notifyChar: CBCharacteristic?

    // MARK: handshake/read state (ported from Explorer)
    private var operation: RingOperation = .takeover
    private var isOnboarding = false        // current run is the pairing wizard
    private var authKey = OuraProtocol.randomAuthKey()
    private enum Step { case idle, notifyEnabled, sentSetAuthKey, sentNonce, sentAuth, reading, done }
    private var step: Step = .idle
    private var readPhase = false
    private var resetSent = false           // ResetMemory written; waiting for the 0x1B ack
    private var resetGraceWork: DispatchWorkItem?
    private var streamLeftover = Data()
    private var ringNowTimestamp: UInt32 = 0
    private var latestSeenTs: UInt32 = 0
    private var allIBIms: [Int] = []
    private var scanFallbackWork: DispatchWorkItem?

    override init() {
        super.init()
        central = CBCentralManager(delegate: self, queue: .main)
    }

    // MARK: - Public API

    /// Start an operation. The ring must be advertising (worn / just off charger).
    func start(_ op: RingOperation) {
        resetSession()
        operation = op
        if case .takeover = op {
            authKey = OuraProtocol.randomAuthKey()
            info("⚠️ Takeover: will set OUR key on the ring. Only on a FACTORY-RESET ring in pairing mode (off charger → back on → white blink).")
        }
        if case .authenticate(let k) = op { authKey = k }
        if case .read(let k) = op { authKey = k }
        if case .factoryReset(let k) = op {
            authKey = k
            info("⚠️ Factory reset: will authenticate with this phone's key, then erase the ring's memory so it can be re-onboarded fresh.")
        }

        switch central.state {
        case .poweredOn: beginScan()
        case .unauthorized: phase = .bluetoothUnavailable("Bluetooth permission denied. Enable it for this app in Settings.")
        case .poweredOff: phase = .bluetoothUnavailable("Bluetooth is off. Turn it on and retry.")
        case .unsupported: phase = .bluetoothUnavailable("This device has no Bluetooth LE.")
        default: phase = .scanning // will begin once state updates to poweredOn
        }
    }

    /// Onboard from zero: generate a FRESH key and claim a factory-reset ring in
    /// pairing mode. Same BLE work as `.takeover`, but drives the wizard's step state
    /// and translates failures into recoverable, user-facing guidance.
    func startOnboarding() {
        resetSession()
        operation = .takeover
        isOnboarding = true
        authKey = OuraProtocol.randomAuthKey()
        info("Onboarding: generated a fresh 16-byte key. Looking for a ring in pairing mode…")

        switch central.state {
        case .poweredOn:
            onboardingStep = .scanning
            beginScan()
        case .unauthorized:
            onboardingStep = .failed(.bluetoothUnavailable("Bluetooth permission is off. Enable it for poura in Settings → poura."))
        case .poweredOff:
            onboardingStep = .failed(.bluetoothUnavailable("Bluetooth is off. Turn it on in Control Center, then retry."))
        case .unsupported:
            onboardingStep = .failed(.bluetoothUnavailable("This device has no Bluetooth LE."))
        default:
            onboardingStep = .scanning   // begins once central reports poweredOn
        }
    }

    /// The freshly-generated takeover key, so the UI can show/save it after success.
    var currentKeyHex: String { authKey.hexString }

    func stop() {
        scanFallbackWork?.cancel()
        if central.state == .poweredOn { central.stopScan() }
        tearDownConnection()
        resetSession()
        phase = .idle
    }

    // MARK: - Internals

    /// Reset only the PER-RUN state (logs, decoded data, handshake step). Deliberately
    /// does NOT touch the live BLE connection (ring/writeChar/notifyChar) — those are
    /// reused across operations so a second "Read"/"Test auth" doesn't have to
    /// re-scan/re-bond a ring that just stopped advertising.
    private func resetSession() {
        scanFallbackWork?.cancel(); scanFallbackWork = nil
        log.removeAll(); battery = nil; firmware = nil; product = nil
        recordCounts.removeAll(); vitals = nil; liveSamples = 0
        step = .idle; readPhase = false; streamLeftover = Data()
        ringNowTimestamp = 0; latestSeenTs = 0; allIBIms = []
        isOnboarding = false
        resetSent = false
        factoryResetSucceeded = false
        resetGraceWork?.cancel(); resetGraceWork = nil
        // NB: don't reset onboardingStep here — the wizard view keeps showing the last
        // outcome (.succeeded/.failed) until the user acts. startOnboarding() sets it.
    }

    /// Fully drop the BLE connection and forget the peripheral/characteristics. Used by
    /// stop() and on a real disconnect — NOT after a successful op (we keep the link).
    private func tearDownConnection() {
        if let r = ring { central.cancelPeripheralConnection(r) }
        ring = nil; writeChar = nil; notifyChar = nil
    }

    /// True when we already hold a usable, connected link to the ring (so we can skip
    /// scanning + service discovery and jump straight to the handshake).
    private var hasLiveConnection: Bool {
        ring?.state == .connected && writeChar != nil && notifyChar != nil
    }

    private func beginScan() {
        phase = .scanning

        // Fastest path: we never dropped the link from the last operation. Re-run the
        // handshake on the existing connection — no scan, no re-discovery, no re-bond.
        // This is what makes a 2nd/3rd "Read"/"Test auth" in a row reliable.
        if hasLiveConnection {
            info("Reusing the existing connection.")
            beginHandshake()
            return
        }

        // Next: the ring is bonded but may NOT re-advertise its service UUID or name for
        // a while after an op (so a fresh scan finds nothing and we hang on "scanning").
        // The system still knows it as a connected peripheral — grab it directly.
        let connected = central.retrieveConnectedPeripherals(withServices: [ouraServiceUUID])
        if let p = connected.first {
            info("Found the ring via system handle (no scan needed).")
            connect(p)
            return
        }

        info("Scanning for the Oura service…")
        // The ring uses a rotating BLE address (RPA) — always connect to the freshly
        // scanned peripheral; never cache its UUID across sessions.
        central.scanForPeripherals(withServices: [ouraServiceUUID], options: nil)
        // Some firmwares don't advertise the service UUID while worn; widen after 4s.
        let work = DispatchWorkItem { [weak self] in
            guard let self, self.ring == nil else { return }
            self.info("No Oura-service advert yet; widening to a full scan…")
            self.central.stopScan()
            self.central.scanForPeripherals(withServices: nil, options: nil)
        }
        scanFallbackWork = work
        DispatchQueue.main.asyncAfter(deadline: .now() + 4, execute: work)

        // Don't scan forever. If nothing shows up after a generous window, fail with a
        // clear message instead of an endless "scanning…".
        delay(25) { [weak self] in
            guard let self, self.ring == nil else { return }
            self.central.stopScan()
            if self.isOnboarding {
                self.failOnboarding(.generic("No ring found in pairing mode. Take it off the charger, put it back on, and watch for the white blinking light — then retry."))
            } else {
                self.finish(success: false, "Couldn't find the ring. Make sure it's worn or near the phone (off the charger), then retry.")
            }
        }
    }

    private func connect(_ p: CBPeripheral) {
        scanFallbackWork?.cancel()
        central.stopScan()
        ring = p
        p.delegate = self
        phase = .connecting
        if isOnboarding { onboardingStep = .connecting }
        info("Connecting to \(p.identifier.uuidString.prefix(8))…")
        central.connect(p, options: nil)
    }

    private func write(_ data: Data, tx: Bool = true) {
        guard let wc = writeChar, let p = ring else { return }
        if tx { self.tx(data) }
        let type: CBCharacteristicWriteType = wc.properties.contains(.write) ? .withResponse : .withoutResponse
        p.writeValue(data, for: wc, type: type)
    }

    private func delay(_ s: Double, _ body: @escaping @MainActor () -> Void) {
        // Hop back onto the main actor after the delay. Using Task (not
        // DispatchQueue.asyncAfter) keeps the closure actor-isolated, so it can touch
        // @Published state without a data-race warning under strict concurrency.
        Task { @MainActor in
            try? await Task.sleep(nanoseconds: UInt64(s * 1_000_000_000))
            body()
        }
    }

    private func finish(success: Bool, _ message: String) {
        guard step != .done else { return }
        step = .done
        if success { logSuccess(message) } else { logError(message) }
        let summary = vitals.map { "  ❤️ \($0.bpm) bpm" } ?? ""
        phase = .done(success: success, message: message + summary)

        // Keep the link ALIVE on success so the next operation can reuse it (no
        // re-scan). Only tear down on failure — a failed link is worth dropping so the
        // next attempt starts clean. The OS reaps the idle connection if the app
        // backgrounds or the ring goes out of range.
        if !success { tearDownConnection() }
    }

    // MARK: - Logging helpers (these append to @Published log)
    private func info(_ s: String)       { log.append(LogLine(text: s, kind: .info)) }
    private func tx(_ d: Data)           { log.append(LogLine(text: "→ \(d.hexSpaced)", kind: .tx)) }
    private func rx(_ d: Data)           { log.append(LogLine(text: "← \(d.hexSpaced)", kind: .rx)) }
    private func bio(_ s: String)        { log.append(LogLine(text: s, kind: .biosignal)) }
    private func logSuccess(_ s: String) { log.append(LogLine(text: "✅ \(s)", kind: .success)) }
    private func logError(_ s: String)   { log.append(LogLine(text: "❌ \(s)", kind: .error)) }
}

// MARK: - CBCentralManagerDelegate
extension RingManager: CBCentralManagerDelegate {
    nonisolated func centralManagerDidUpdateState(_ central: CBCentralManager) {
        Task { @MainActor in
            switch central.state {
            case .poweredOn:
                if case .scanning = self.phase { self.beginScan() }
            case .poweredOff:
                self.phase = .bluetoothUnavailable("Bluetooth is off.")
            case .unauthorized:
                self.phase = .bluetoothUnavailable("Bluetooth permission denied for this app.")
            case .unsupported:
                self.phase = .bluetoothUnavailable("Bluetooth LE unsupported.")
            default: break
            }
        }
    }

    nonisolated func centralManager(_ central: CBCentralManager, didDiscover peripheral: CBPeripheral,
                                    advertisementData: [String: Any], rssi RSSI: NSNumber) {
        let advName = (advertisementData[CBAdvertisementDataLocalNameKey] as? String) ?? peripheral.name ?? ""
        let advertisesOura = (advertisementData[CBAdvertisementDataServiceUUIDsKey] as? [CBUUID])?.contains(ouraServiceUUID) ?? false
        guard advertisesOura || advName.lowercased().contains("oura") else { return }
        Task { @MainActor in
            guard self.ring == nil else { return }
            self.info("Found ring \"\(advName.isEmpty ? "Oura" : advName)\" rssi=\(RSSI.intValue)")
            self.connect(peripheral)
        }
    }

    nonisolated func centralManager(_ central: CBCentralManager, didConnect peripheral: CBPeripheral) {
        Task { @MainActor in
            self.phase = .discovering
            self.info("Connected. Discovering services…")
            peripheral.discoverServices([ouraServiceUUID])
        }
    }

    nonisolated func centralManager(_ central: CBCentralManager, didFailToConnect peripheral: CBPeripheral, error: Error?) {
        Task { @MainActor in
            let msg = error?.localizedDescription ?? "unknown"
            if self.isOnboarding {
                self.failOnboarding(msg.lowercased().contains("pairing") ? .staleBond : .generic("Couldn't connect: \(msg)"))
            }
            self.finish(success: false, "Failed to connect: \(msg)")
        }
    }

    nonisolated func centralManager(_ central: CBCentralManager, didDisconnectPeripheral peripheral: CBPeripheral, error: Error?) {
        Task { @MainActor in
            // The link is gone — forget the peripheral + chars so hasLiveConnection is
            // false and the next op re-acquires via retrieve/scan instead of writing to
            // a dead handle.
            self.ring = nil; self.writeChar = nil; self.notifyChar = nil

            guard let e = error else { return }   // clean disconnect (e.g. our stop()) — nothing to report
            let pairing = e.localizedDescription.lowercased().contains("pairing")
            if pairing {
                self.info("Disconnected (stale bond). If pairing keeps failing, forget the ring under Settings → Bluetooth.")
            }
            // If we dropped mid-handshake (not after a clean .done), surface it.
            if self.isOnboarding, self.step != .done {
                self.failOnboarding(pairing ? .staleBond : .generic("Lost the connection: \(e.localizedDescription)"))
            } else if self.step != .done {
                self.finish(success: false, "Lost the connection: \(e.localizedDescription)")
            }
        }
    }
}

// MARK: - CBPeripheralDelegate
extension RingManager: CBPeripheralDelegate {
    nonisolated func peripheral(_ peripheral: CBPeripheral, didDiscoverServices error: Error?) {
        Task { @MainActor in
            guard let svc = peripheral.services?.first(where: { $0.uuid == ouraServiceUUID }) else {
                self.finish(success: false, "Oura service not found on this peripheral."); return
            }
            peripheral.discoverCharacteristics([ouraWriteCharUUID, ouraNotifyCharUUID], for: svc)
        }
    }

    nonisolated func peripheral(_ peripheral: CBPeripheral, didDiscoverCharacteristicsFor service: CBService, error: Error?) {
        Task { @MainActor in
            for c in service.characteristics ?? [] {
                if c.uuid == ouraNotifyCharUUID { self.notifyChar = c }
                if c.uuid == ouraWriteCharUUID { self.writeChar = c }
            }
            guard let nc = self.notifyChar, self.writeChar != nil else {
                self.finish(success: false, "Missing Oura write/notify characteristics."); return
            }
            self.info("Found command + notify chars. Enabling notifications…")
            peripheral.setNotifyValue(true, for: nc)
        }
    }

    nonisolated func peripheral(_ peripheral: CBPeripheral, didUpdateNotificationStateFor characteristic: CBCharacteristic, error: Error?) {
        Task { @MainActor in
            guard characteristic == self.notifyChar, self.step == .idle else { return }
            if let e = error { self.finish(success: false, "Enable notify failed: \(e.localizedDescription)"); return }
            self.beginHandshake()
        }
    }

    /// Kick off the auth handshake. Entry point for BOTH paths: a fresh connection
    /// (after notifications are enabled) and a reused live connection (notify already on).
    @MainActor private func beginHandshake() {
        guard step == .idle else { return }
        step = .notifyEnabled
        phase = .authenticating
        if isOnboarding { onboardingStep = .claiming }
        switch operation {
        case .takeover:
            info("Notifications on. Setting OUR auth_key…")
            step = .sentSetAuthKey
            write(OuraProtocol.setAuthKey(authKey))
        case .authenticate, .read, .factoryReset:
            info("Authenticating with saved key…")
            step = .sentNonce
            write(OuraProtocol.getAuthNonce())
        }
    }

    nonisolated func peripheral(_ peripheral: CBPeripheral, didUpdateValueFor characteristic: CBCharacteristic, error: Error?) {
        guard characteristic.uuid == ouraNotifyCharUUID, let data = characteristic.value else { return }
        Task { @MainActor in
            if self.readPhase { self.handleReadNotification(data); return }
            self.rx(data)
            self.handleHandshake(OuraProtocol.parseNotification(data))
        }
    }

    // MARK: handshake responses (ported from handleTakeoverNotification)
    @MainActor private func handleHandshake(_ parsed: (kind: String, payload: Data)) {
        switch parsed.kind {
        case "setauthkey":
            let code = parsed.payload.first ?? 0xFF
            if code == 0x00 || code == 0x05 {
                logSuccess("SetAuthKey accepted. Requesting nonce…")
                step = .sentNonce
                write(OuraProtocol.getAuthNonce())
            } else {
                // A claimed ring refuses a new key. During onboarding that means
                // "factory-reset me first".
                if isOnboarding { failOnboarding(.ringAlreadyClaimed) }
                finish(success: false, "SetAuthKey rejected (0x\(String(format: "%02x", code))). Ring not factory-reset?")
            }
        case "nonce":
            guard parsed.payload.count == 15,
                  let proof = OuraProtocol.computeProof(authKey: authKey, nonce15: parsed.payload) else {
                if isOnboarding { failOnboarding(.generic("The ring sent a malformed nonce.")) }
                finish(success: false, "Bad nonce / proof computation failed."); return
            }
            step = .sentAuth
            write(OuraProtocol.authenticate(proof: proof))
        case "auth":
            let code = parsed.payload.first ?? 0xFF
            guard code == 0x00 else {
                let meaning = ["01": "auth error", "02": "in factory reset", "03": "not original onboarded device"][String(format: "%02x", code)] ?? "unknown"
                if isOnboarding {
                    switch code {
                    case 0x02: failOnboarding(.ringInFactoryReset)
                    case 0x03: failOnboarding(.ringAlreadyClaimed)
                    default:   failOnboarding(.generic("Authenticate failed (0x\(String(format: "%02x", code)) = \(meaning))."))
                    }
                }
                finish(success: false, "Authenticate failed (0x\(String(format: "%02x", code)) = \(meaning))."); return
            }
            logSuccess("Authenticated with our key.")
            switch operation {
            case .read: startReadSequence()
            case .factoryReset: startFactoryReset()
            case .takeover:
                let stored = Keychain.storeAuthKey(authKey)
                if isOnboarding {
                    if stored {
                        onboardingStep = .succeeded(keyHex: authKey.hexString)
                        finish(success: true, "Onboarding complete — ring claimed with our key.")
                    } else {
                        failOnboarding(.generic("Claimed the ring, but couldn't save the key to the Keychain. Write it down: \(authKey.hexString)"))
                        finish(success: false, "Keychain save failed.")
                    }
                } else {
                    _ = stored
                    finish(success: true, "Takeover complete. Key saved to Keychain.")
                }
            case .authenticate:
                finish(success: true, "Persistence confirmed — the ring remembered our key.")
            }
        default:
            // In factory-reset mode, a 0x1B response is the ResetMemory ack.
            if resetSent, parsed.payload.first == 0x1B {
                completeFactoryReset(acked: true)
            }
        }
    }

    /// Set the wizard's failure state and tear down the BLE session. Distinct from
    /// `finish` so the onboarding view shows recoverable guidance, not a dead end.
    @MainActor private func failOnboarding(_ reason: OnboardingFailure) {
        onboardingStep = .failed(reason)
        logError(reason.title)
    }

    // MARK: factory reset (ported from ble-explorer's `--reset`, same verified frame)
    /// Authenticated with our key — now erase the ring's memory so it returns to
    /// pairing mode and can be re-onboarded (by this app or the Oura app) fresh.
    /// Mirrors the VERIFIED macOS sequence: ResetMemory(false) = [0x1A 0x00], whose
    /// ack is a notification whose first byte is 0x1B. Some firmwares reset without
    /// replying, so a grace timer finishes the op even if no ack arrives.
    @MainActor private func startFactoryReset() {
        guard !resetSent else { return }
        resetSent = true
        phase = .authenticating
        info("→ ResetMemory (factory reset, [0x1A 0x00])…")
        write(Data([OuraOpcode.resetMemory, 0x00]))   // matches the app's ResetMemory(false)

        let work = DispatchWorkItem { [weak self] in
            self?.completeFactoryReset(acked: false)
        }
        resetGraceWork = work
        DispatchQueue.main.asyncAfter(deadline: .now() + 4, execute: work)
    }

    /// Finish a factory-reset op exactly once — whether the 0x1B ack arrived or the
    /// grace timer fired first. Tears the link down (the ring is rebooting) so we
    /// don't try to reuse a dead connection.
    @MainActor private func completeFactoryReset(acked: Bool) {
        guard resetSent, step != .done else { return }
        resetGraceWork?.cancel(); resetGraceWork = nil
        resetSent = false
        if acked { logSuccess("ResetMemory acknowledged by the ring.") }
        finish(success: true,
               "Factory reset sent. The ring is erasing its memory — leave it still ~2 min. It can now be re-onboarded.")
        tearDownConnection()   // finish() keeps the link on success; a resetting ring won't honor it.
        factoryResetSucceeded = true
    }

    /// Called by the UI once it has handled `factoryResetSucceeded` (deleted the key,
    /// signed out). Clears the flag so it doesn't re-trigger.
    func acknowledgeFactoryReset() { factoryResetSucceeded = false }

    // MARK: read sequence (ported from startReadSequence, same verified timings)
    @MainActor private func startReadSequence() {
        guard !readPhase else { return }
        readPhase = true
        step = .reading
        phase = .reading
        diag = ReadDiagnostics()
        info("Authenticated. Running read sequence — wear the ring, keep still.")

        let now = UInt32(Date().timeIntervalSince1970)
        write(OuraProtocol.setBleMode(0x02))
        delay(0.4) { self.write(OuraProtocol.syncTime(unix: now)) }
        delay(0.8) { self.write(OuraProtocol.setNotification(0xbf)) }
        delay(1.3) { self.write(OuraProtocol.getFirmwareVersion()) }
        delay(1.8) { self.write(OuraProtocol.getBatteryLevel()) }

        let subs: [UInt8] = [0x14, 0x18, 0x28, 0x34, 0x04, 0x08]
        for (n, sub) in subs.enumerated() {
            delay(2.3 + Double(n) * 0.4) { self.write(OuraProtocol.getProductInfo(sub: sub)) }
        }

        // Feature subscribe = measurement trigger (feature 0x02): get → set=0x03 → subscribe=0x02.
        let subStart = 2.3 + Double(subs.count) * 0.4 + 0.5
        delay(subStart)        { self.write(OuraProtocol.featureGet(0x02)) }
        delay(subStart + 0.3)  { self.write(OuraProtocol.featureSet(0x02, 0x03)) }
        delay(subStart + 0.6)  { self.write(OuraProtocol.featureSubscribe(0x02, 0x02)) }

        let afterInfo = subStart + 0.9 + 0.5
        delay(afterInfo) {
            self.info("data_flush — release buffered events…")
            self.write(OuraProtocol.dataFlush())
        }

        // GetEvent from a RECENT cursor is where the real biosignals come from (not the
        // live AFE channel). ringNowTimestamp comes from the SyncTime ack above.
        if fetchRecentHistory {
            delay(afterInfo + 0.5) {
                self.info("GetEvent from recent cursor 0x\(String(format: "%08x", self.recentCursor()))…")
                self.sendGetEvent(self.recentCursor())
            }
        }

        let streamStart = afterInfo + (fetchRecentHistory ? 1.0 : 0.4)
        delay(streamStart) { self.info("Reading for \(Int(self.streamSeconds))s — keep the ring on and still…") }

        // DHR burst: ACTIVELY drive the ring to measure HR. open_ring §6.7 — DHR mode
        // (feature 0x02) auto-reverts to off after ~20s, so re-engage `set 0x02=0x03`
        // + `subscribe 0x02=0x02` every ~12s. The CLI verified that under burst the ring
        // logs IBI(0x80)/temp records (which `data_flush` + drain then pull). Without
        // this, an idle ring just emits the slow AFE channel and logs no heart-rate data.
        if burstMode {
            var t = streamStart + 0.2
            while t < streamStart + streamSeconds {
                delay(t)        { self.write(OuraProtocol.featureSet(0x02, 0x03)) }
                delay(t + 0.3)  { self.write(OuraProtocol.featureSubscribe(0x02, 0x02)) }
                delay(t + 0.6)  { self.write(OuraProtocol.dataFlush()) }   // flush what the burst just measured
                t += 12.0
            }
        }

        // Drain: every ~2.5s, re-issue GetEvent from the latest ringTimestamp seen, to
        // pull records as the worn ring measures. Matches the Mac CLI's proven `--drain`
        // exactly (latestSeenTs+1, else the tight recent cursor). With the tight window
        // above, the first fetch lands near the live edge, so this walks the fresh
        // records forward rather than crawling up from the old log tail.
        if drainMode {
            var t = streamStart + 1.0
            while t < streamStart + streamSeconds {
                delay(t) {
                    let cur = self.latestSeenTs > 0 ? self.latestSeenTs + 1 : self.recentCursor()
                    self.sendGetEvent(cur)
                }
                t += 2.5
            }
        }

        delay(streamStart + streamSeconds) { self.finishRead() }
    }

    /// Send a GetEvent and record the cursor for diagnostics.
    private func sendGetEvent(_ cursor: UInt32) {
        diag.lastCursor = cursor
        diag.getEventCount += 1
        write(OuraProtocol.getEvent(cursor: cursor))
    }

    /// Cursor for "recent" records: ring-now minus a TIGHT look-back window, matching
    /// the Mac CLI's proven `--cursor recent` (0x2000 ≈ a few minutes).
    ///
    /// Why tight, not wide: a GetEvent returns the OLDEST `maxEvents` (255) records at
    /// or after the cursor. With a wide window (we previously used 0x20000) those 255
    /// slots fill with old temp/diag/charge records and never reach the recent IBI near
    /// ring-now — exactly the "latest record stuck 129k ticks behind" symptom. Starting
    /// close to the live edge makes the 255 returned records BE the recent biosignals.
    private func recentCursor() -> UInt32 {
        let window: UInt32 = 0x2000
        return ringNowTimestamp > window ? ringNowTimestamp - window : 0
    }

    // MARK: read notifications (ported from handleReadNotification)
    @MainActor private func handleReadNotification(_ data: Data) {
        guard let tag = data.first else { return }
        let body = data.count > 2 ? Data(data.dropFirst(2)) : Data()
        switch tag {
        case 0x09: firmware = body.asciiToken; info("firmware: \(firmware ?? "?")")
        case 0x0D: battery = body.first.map(Int.init); info("battery: \(battery.map { "\($0)%" } ?? "?")")
        case 0x19:
            // Product info arrives across several sub-queries (hw type, serial, build…).
            // Each carries one ASCII token amid framing bytes — extract the longest run
            // and collect distinct, non-trivial tokens rather than concatenating raw.
            if let tok = body.asciiToken, tok.count >= 3 {
                var parts = product.map { $0.split(separator: " ").map(String.init) } ?? []
                if !parts.contains(tok) { parts.append(tok) }
                product = parts.joined(separator: " ")
                info("product: \(tok)")
            }
        case 0x11: ingest(body)                       // GetEvent history chunk
        case 0x13:                                     // SyncTime ack → ring's current ts
            if body.count >= 4 {
                ringNowTimestamp = UInt32(body[0]) | (UInt32(body[1])<<8) | (UInt32(body[2])<<16) | (UInt32(body[3])<<24)
                diag.ringNowTs = ringNowTimestamp
                diag.syncAckSeen = true
                info("SyncTime ack: ring-now ts = 0x\(String(format: "%08x", ringNowTimestamp))")
            }
        case 0x2F:
            let b = [UInt8](data)
            if b.count >= 10, b[2] == 0x28 { liveSamples += 1; diag.afeSamples += 1 } // live AFE sample
        case 0x17, 0x1D, 0x29: break                   // SetBleMode / SetNotification / data_flush acks
        default: ingest(data)                          // unsolicited stream → TLV
        }
    }

    @MainActor private func ingest(_ data: Data) {
        streamLeftover.append(data)
        let (records, leftover) = OuraProtocol.decodeRecords(streamLeftover)
        streamLeftover = leftover
        let bioTypes: Set<UInt8> = [0x46, 0x47, 0x5d, 0x60, 0x80, 0x81]
        for r in records {
            recordCounts[r.type, default: 0] += 1
            if r.ringTimestamp > latestSeenTs { latestSeenTs = r.ringTimestamp; diag.latestRecordTs = r.ringTimestamp }
            if bioTypes.contains(r.type) { diag.bioRecordCount += 1 }
            if let decoded = OuraProtocol.decodeBiosignal(r) {
                bio("\(OuraProtocol.recordTypeName(r.type)): \(decoded)")
                allIBIms.append(contentsOf: OuraProtocol.ibiValues(r))
            }
        }
        recomputeVitals()
    }

    @MainActor private func recomputeVitals() {
        guard allIBIms.count >= 3 else { return }
        let n = Double(allIBIms.count)
        let mean = Double(allIBIms.reduce(0, +)) / n
        var sq = 0.0
        for k in 1..<allIBIms.count { let d = Double(allIBIms[k] - allIBIms[k-1]); sq += d*d }
        let rmssd = (sq / Double(allIBIms.count - 1)).squareRoot()
        vitals = VitalsSummary(bpm: Int((60000.0 / mean).rounded()),
                               meanIBIms: Int(mean.rounded()),
                               beats: allIBIms.count,
                               rmssdMs: Int(rmssd.rounded()))
    }

    @MainActor private func finishRead() {
        let total = recordCounts.values.reduce(0, +)
        // Biosignal record types (HR/HRV/temp/accel) vs. pure telemetry (0x43 log, 0x61 debug).
        let bioTypes: Set<UInt8> = [0x46, 0x47, 0x5d, 0x60, 0x80, 0x81]
        let gotBio = recordCounts.keys.contains { bioTypes.contains($0) }

        let msg: String
        if total == 0 {
            msg = "No records. Make sure the ring is on your finger and off the charger, then retry."
        } else if !gotBio {
            // Telemetry only. Use the diagnostics to say WHY honestly: a frozen/lagging
            // log means the ring isn't writing measurement records (needs sustained wear
            // to run a session), not that we're fetching wrong.
            if diag.logIsFresh {
                msg = "Got \(total) records, all telemetry — the ring's log is current but holds no heart-rate data. It isn't running a PPG measurement session right now. Keep wearing it; check the Diagnostics card."
            } else {
                msg = "Got \(total) records but the ring hasn't logged measurements recently (log lag \(diag.recordLagTicks) ticks). A freshly-reset ring needs to be worn a while before it records IBI/temp. Wear it for a few hours, then read again."
            }
        } else {
            let hr = vitals.map { " ❤️ \($0.bpm) bpm" } ?? ""
            msg = "Read complete. \(total) records across \(recordCounts.count) types.\(hr)"
        }
        finish(success: true, msg)
    }
}

private extension Data {
    /// The longest contiguous run of printable-ASCII bytes, as a String (nil if none).
    /// Info responses wrap one real token (e.g. "ORE_06", a serial) in framing/length
    /// bytes; this pulls out the token instead of smearing the framing into the text.
    var asciiToken: String? {
        var best = "", cur = ""
        for b in self {
            if (0x20...0x7e).contains(b) { cur.append(Character(UnicodeScalar(b))) }
            else { if cur.count > best.count { best = cur }; cur = "" }
        }
        if cur.count > best.count { best = cur }
        let trimmed = best.trimmingCharacters(in: CharacterSet(charactersIn: " !\"#()[]{}<>*"))
        return trimmed.isEmpty ? nil : trimmed
    }
}
