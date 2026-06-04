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

// Known Oura Ring 4 GATT identifiers (from research — to be VALIDATED against the
// real ring; see docs/PROTOCOL.md). The primary custom service:
let ouraServiceUUID = CBUUID(string: "98ed0001-a541-11e4-b6a0-0002a5d5c51b")
let ouraNotifyCharUUID = CBUUID(string: "98ed0003-a541-11e4-b6a0-0002a5d5c51b")

// Standard services worth reading for context (cleartext, no auth needed):
let batteryServiceUUID = CBUUID(string: "180F")
let deviceInfoServiceUUID = CBUUID(string: "180A")

enum Mode {
    case scanAll
    case ouraOnly
    case connect(uuid: UUID)
    case byName(substring: String)
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
            log("[ble] Peripheral \(uuid) not cached; scanning to find it…")
            central.scanForPeripherals(withServices: nil, options: [CBCentralManagerScanOptionAllowDuplicatesKey: false])
        case .ouraOnly:
            log("[ble] Scanning for Oura service \(ouraServiceUUID.uuidString)…")
            // Scan with the service filter; some peripherals only advertise the
            // service in the scan response, so also keep a broad fallback.
            central.scanForPeripherals(withServices: [ouraServiceUUID], options: nil)
            // Fallback broad scan after a short delay if nothing shows up.
            DispatchQueue.main.asyncAfter(deadline: .now() + 4) { [weak self] in
                guard let self, self.target == nil else { return }
                self.log("[ble] No Oura-service advert yet; widening to a full scan (matching by name 'oura' too)…")
                self.central.stopScan()
                self.central.scanForPeripherals(withServices: nil, options: nil)
            }
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
        discovered[peripheral.identifier] = (peripheral, advName, RSSI.intValue)

        switch mode {
        case .scanAll:
            // Live print as we discover.
            log(String(format: "[scan] %@  rssi=%-4d  %@  svc=[%@]", peripheral.identifier.uuidString, RSSI.intValue, advName, svcs))
        case .ouraOnly:
            let advertisesOura = (advertisementData[CBAdvertisementDataServiceUUIDsKey] as? [CBUUID])?.contains(ouraServiceUUID) ?? false
            if advertisesOura || advName.lowercased().contains("oura") {
                log("[ble] Found candidate Oura device: \(advName) [\(peripheral.identifier.uuidString)] rssi=\(RSSI.intValue)")
                central.stopScan()
                connect(peripheral)
            }
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

    func connect(_ peripheral: CBPeripheral) {
        target = peripheral
        peripheral.delegate = self
        log("[ble] Connecting to \(peripheral.identifier.uuidString)…")
        central.connect(peripheral, options: nil)
    }

    func centralManager(_ central: CBCentralManager, didConnect peripheral: CBPeripheral) {
        log("[ble] Connected. Name=\(peripheral.name ?? "(nil)"). Discovering services…")
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
            // Read any readable characteristic (read-only behavior).
            if c.properties.contains(.read) {
                pendingReads += 1
                peripheral.readValue(for: c)
            }
            // Also discover descriptors for completeness.
            peripheral.discoverDescriptors(for: c)
        }
        checkDone(peripheral)
    }

    func peripheral(_ peripheral: CBPeripheral, didUpdateValueFor characteristic: CBCharacteristic, error: Error?) {
        pendingReads = max(0, pendingReads - 1)
        if let error {
            log("      [read] \(characteristic.uuid.uuidString): error \(error.localizedDescription)")
        } else if let data = characteristic.value {
            log("      [read] \(characteristic.uuid.uuidString): \(data.count)B  hex=[\(hex(data))]  ascii=\"\(ascii(data))\"")
        }
        checkDone(peripheral)
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
let explorer = Explorer(mode: mode, scanSeconds: scanSeconds)

// Overall safety timeout so the process never hangs forever.
DispatchQueue.main.asyncAfter(deadline: .now() + max(scanSeconds + 40, 60)) {
    FileHandle.standardError.write(Data("[ble] Global timeout reached; exiting.\n".utf8))
    exit(0)
}

RunLoop.main.run()
