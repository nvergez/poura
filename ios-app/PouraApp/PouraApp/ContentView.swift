import SwiftUI
import PouraCore

/// Main screen, shown once the ring is onboarded (a 16-byte key is saved).
struct ContentView: View {
    @EnvironmentObject var ring: RingManager
    /// Called when the user deletes the saved key — returns the app to onboarding.
    var onSignedOut: () -> Void

    @State private var savedKeyHex: String = Keychain.loadAuthKey()?.hexString ?? ""
    @State private var showKeySheet = false

    private var hasKey: Bool { Data(hexString: savedKeyHex)?.count == 16 }

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 16) {
                    phaseCard
                    if ring.vitals != nil || ring.battery != nil { vitalsCard }
                    actionButtons
                    if ring.diag.getEventCount > 0 { diagCard }
                    if !ring.recordCounts.isEmpty { recordsCard }
                    logCard
                }
                .padding()
            }
            .navigationTitle("poura")
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Button { showKeySheet = true } label: { Image(systemName: "key.fill") }
                }
            }
            .sheet(isPresented: $showKeySheet) {
                KeySheet(savedKeyHex: $savedKeyHex, onSignedOut: onSignedOut)
                    .environmentObject(ring)
            }
        }
        .onChange(of: ring.factoryResetSucceeded) { succeeded in
            // The ring was erased over BLE — the saved key no longer authenticates to
            // anything, so drop it and return to onboarding. Done here (not in KeySheet)
            // because the sheet has already dismissed by the time the async reset lands.
            guard succeeded else { return }
            Keychain.deleteAuthKey()
            savedKeyHex = ""
            ring.acknowledgeFactoryReset()
            onSignedOut()
        }
    }

    // MARK: cards

    private var phaseCard: some View {
        HStack {
            Image(systemName: phaseIcon).font(.title2).foregroundStyle(phaseColor)
            Text(phaseText).font(.headline)
            Spacer()
        }
        .padding()
        .background(.thinMaterial, in: RoundedRectangle(cornerRadius: 12))
    }

    private var vitalsCard: some View {
        VStack(alignment: .leading, spacing: 8) {
            if let v = ring.vitals {
                HStack(alignment: .firstTextBaseline) {
                    Text("❤️ \(v.bpm)").font(.system(size: 44, weight: .bold))
                    Text("bpm").foregroundStyle(.secondary)
                    Spacer()
                    VStack(alignment: .trailing) {
                        Text("HRV \(v.rmssdMs) ms").font(.subheadline)
                        Text("\(v.beats) beats").font(.caption).foregroundStyle(.secondary)
                    }
                }
            }
            HStack(spacing: 16) {
                if let b = ring.battery { Label("\(b)%", systemImage: "battery.100") }
                if let f = ring.firmware { Label(f, systemImage: "cpu") }
            }
            .font(.caption).foregroundStyle(.secondary)
            if let p = ring.product { Text(p).font(.caption2).foregroundStyle(.secondary) }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding()
        .background(.thinMaterial, in: RoundedRectangle(cornerRadius: 12))
    }

    private var actionButtons: some View {
        VStack(spacing: 10) {
            Button {
                guard let k = Data(hexString: savedKeyHex), k.count == 16 else { return }
                ring.start(.read(k))
            } label: { Label("Read biosignals", systemImage: "waveform.path.ecg").frame(maxWidth: .infinity) }
            .buttonStyle(.borderedProminent)
            .disabled(!hasKey || isBusy)

            Button {
                guard let k = Data(hexString: savedKeyHex), k.count == 16 else { return }
                ring.start(.authenticate(k))
            } label: { Label("Test authentication", systemImage: "checkmark.shield").frame(maxWidth: .infinity) }
            .buttonStyle(.bordered)
            .disabled(!hasKey || isBusy)

            if isBusy {
                Button(role: .destructive) { ring.stop() } label: {
                    Label("Stop", systemImage: "stop.fill").frame(maxWidth: .infinity)
                }
                .buttonStyle(.bordered)
            }
        }
    }

    private var diagCard: some View {
        let d = ring.diag
        return VStack(alignment: .leading, spacing: 6) {
            Text("Diagnostics").font(.headline)
            diagRow("Ring-now ts", d.syncAckSeen ? String(format: "0x%08x", d.ringNowTs) : "⚠️ no SyncTime ack",
                    ok: d.syncAckSeen && d.ringNowTs > 0)
            diagRow("Last cursor", String(format: "0x%08x", d.lastCursor), ok: d.lastCursor > 0)
            diagRow("GetEvent calls", "\(d.getEventCount)", ok: true)
            diagRow("Latest record ts", String(format: "0x%08x", d.latestRecordTs), ok: d.latestRecordTs > 0)
            diagRow("Log lag (ticks)", d.latestRecordTs > 0 ? String(format: "%d (0x%x)", d.recordLagTicks, d.recordLagTicks) : "—",
                    ok: d.logIsFresh)
            diagRow("Biosignal records", "\(d.bioRecordCount)", ok: d.bioRecordCount > 0)
            diagRow("Live AFE samples", "\(d.afeSamples)", ok: d.afeSamples > 0)
            if d.bioRecordCount == 0 && d.getEventCount > 1 {
                Text(interpretation(d))
                    .font(.caption2).foregroundStyle(.secondary).padding(.top, 4)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding()
        .background(.thinMaterial, in: RoundedRectangle(cornerRadius: 12))
    }

    private func diagRow(_ label: String, _ value: String, ok: Bool) -> some View {
        HStack {
            Image(systemName: ok ? "checkmark.circle.fill" : "circle")
                .font(.caption2).foregroundStyle(ok ? Color.green : Color.secondary)
            Text(label).font(.caption)
            Spacer()
            Text(value).font(.system(.caption, design: .monospaced)).foregroundStyle(.secondary)
        }
    }

    /// Honest, data-driven read of why a session produced no heart-rate data.
    private func interpretation(_ d: ReadDiagnostics) -> String {
        if !d.syncAckSeen || d.ringNowTs == 0 {
            return "No SyncTime ack — we don't know the ring's current time, so the cursor can't target recent records. This IS a fetch problem; tell me and we'll dig in."
        }
        if d.logIsFresh {
            return "The fetch is healthy and reaching the newest records, but none are heart-rate type — the ring is logging telemetry only. It hasn't run a PPG measurement session. AFE is streaming (\(d.afeSamples) samples), so the sensor is on; the ring just isn't recording IBI right now."
        }
        return "The newest logged record trails the ring's clock by \(d.recordLagTicks) ticks — the ring stopped writing records a while ago (idle, no measurement session since the reset). Wear it continuously and keep still; a session writes IBI/temp the fetch can then pick up."
    }

    private var recordsCard: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text("Records").font(.headline)
            ForEach(ring.recordCounts.sorted(by: { $0.key < $1.key }), id: \.key) { t, c in
                HStack {
                    Text(String(format: "0x%02x", t)).monospaced().foregroundStyle(.secondary)
                    Text(OuraProtocol.recordTypeName(t))
                    Spacer()
                    Text("\(c)").monospaced()
                }.font(.caption)
            }
            if ring.liveSamples > 0 {
                Text("live AFE samples: \(ring.liveSamples)").font(.caption2).foregroundStyle(.secondary)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding()
        .background(.thinMaterial, in: RoundedRectangle(cornerRadius: 12))
    }

    private var logCard: some View {
        VStack(alignment: .leading, spacing: 2) {
            Text("Log").font(.headline).padding(.bottom, 4)
            ForEach(ring.log.suffix(80)) { line in
                Text(line.text)
                    .font(.system(.caption2, design: .monospaced))
                    .foregroundStyle(color(for: line.kind))
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding()
        .background(Color(.secondarySystemBackground), in: RoundedRectangle(cornerRadius: 12))
    }

    // MARK: helpers

    private var isBusy: Bool {
        switch ring.phase {
        case .idle, .done, .bluetoothUnavailable: return false
        default: return true
        }
    }

    private func color(for k: LogLine.Kind) -> Color {
        switch k {
        case .info: return .secondary
        case .tx: return .blue
        case .rx: return .purple
        case .biosignal: return .green
        case .success: return .green
        case .error: return .red
        }
    }

    private var phaseText: String {
        switch ring.phase {
        case .idle: return "Ready"
        case .bluetoothUnavailable(let m): return m
        case .scanning: return "Scanning…"
        case .connecting: return "Connecting…"
        case .discovering: return "Discovering…"
        case .authenticating: return "Authenticating…"
        case .reading: return "Reading…"
        case .done(_, let m): return m
        }
    }

    private var phaseIcon: String {
        switch ring.phase {
        case .idle: return "circle"
        case .bluetoothUnavailable: return "exclamationmark.triangle.fill"
        case .scanning, .connecting, .discovering: return "dot.radiowaves.left.and.right"
        case .authenticating: return "lock"
        case .reading: return "waveform"
        case .done(let ok, _): return ok ? "checkmark.circle.fill" : "xmark.circle.fill"
        }
    }

    private var phaseColor: Color {
        switch ring.phase {
        case .done(let ok, _): return ok ? .green : .red
        case .bluetoothUnavailable: return .orange
        default: return .accentColor
        }
    }
}

/// View / export the auth key, or factory-reset the ring (which also signs out).
struct KeySheet: View {
    @EnvironmentObject var ring: RingManager
    @Binding var savedKeyHex: String
    var onSignedOut: () -> Void
    @Environment(\.dismiss) private var dismiss
    @State private var confirmingReset = false

    private var canReset: Bool {
        Data(hexString: savedKeyHex)?.count == 16 && !isBusy
    }

    private var isBusy: Bool {
        switch ring.phase {
        case .idle, .done, .bluetoothUnavailable: return false
        default: return true
        }
    }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    KeyChip(keyHex: savedKeyHex)
                } header: {
                    Text("This phone's auth key")
                } footer: {
                    Text("The 16-byte key this phone uses to authenticate to the ring. Stored device-only (not iCloud-synced). Back it up — it's your only way to re-pair without a factory reset.")
                }
                Section {
                    Button("Factory reset", role: .destructive) {
                        confirmingReset = true
                    }
                    .disabled(!canReset)
                } footer: {
                    Text("Authenticates with this key, then erases the ring's memory over Bluetooth so it returns to pairing mode — re-onboard it here or in the Oura app. This also removes the key from this phone. The ring must be off the charger and in range.")
                }
            }
            .navigationTitle("Key")
            .toolbar { ToolbarItem(placement: .confirmationAction) { Button("Done") { dismiss() } } }
            .confirmationDialog("Factory reset the ring?", isPresented: $confirmingReset, titleVisibility: .visible) {
                Button("Factory reset", role: .destructive) { startFactoryReset() }
                Button("Cancel", role: .cancel) {}
            } message: {
                Text("This erases all data on the ring and unpairs it from this phone. It can't be undone. You'll need to onboard the ring again to use it.")
            }
        }
    }

    /// Kick off the BLE factory reset, then dismiss so the user watches progress on the
    /// main screen. The key is deleted + sign-out happens only AFTER the reset succeeds
    /// (ContentView observes `ring.factoryResetSucceeded`) — never before, so a failed
    /// reset leaves the key intact for a retry instead of stranding the user.
    private func startFactoryReset() {
        guard let key = Data(hexString: savedKeyHex), key.count == 16 else { return }
        ring.start(.factoryReset(key))
        dismiss()
    }
}
