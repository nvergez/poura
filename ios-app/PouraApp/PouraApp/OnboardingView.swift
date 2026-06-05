import SwiftUI
import PouraCore

/// First-run pairing wizard. Walks the user from "I have an Oura Ring 4" to a ring
/// claimed with a fresh key owned by this phone — no Oura app, no Oura cloud.
///
/// Flow:
///   intro  → instructions (pairing mode) → live progress → success / recoverable failure
struct OnboardingView: View {
    @EnvironmentObject var ring: RingManager
    /// Called once the ring is claimed and the key is saved, so the app can move on.
    var onComplete: () -> Void

    enum Page { case intro, prepare, running }
    @State private var page: Page = .intro

    var body: some View {
        VStack {
            switch page {
            case .intro:   intro
            case .prepare: prepare
            case .running: running
            }
        }
        .padding()
        .animation(.default, value: page)
        .animation(.default, value: ring.onboardingStep)
    }

    // MARK: 1. Intro

    private var intro: some View {
        VStack(spacing: 24) {
            Spacer()
            Image(systemName: "circle.circle")
                .font(.system(size: 72))
                .foregroundStyle(.tint)
            Text("Welcome to poura")
                .font(.largeTitle.bold())
            Text("Pair your own Oura Ring 4 directly with this phone and read its biosignals — heart rate, HRV, temperature — without the Oura app or cloud.")
                .multilineTextAlignment(.center)
                .foregroundStyle(.secondary)
            VStack(alignment: .leading, spacing: 12) {
                bullet("key.horizontal", "This phone generates its OWN key and claims the ring.")
                bullet("lock.shield", "The key is stored only on this device (not iCloud).")
                bullet("exclamationmark.triangle", "Pairing requires a FACTORY-RESET ring. If the Oura app still uses it, reset it first.")
            }
            .padding(.vertical)
            Spacer()
            Button {
                page = .prepare
            } label: { Text("Get started").frame(maxWidth: .infinity) }
            .buttonStyle(.borderedProminent)
            .controlSize(.large)
        }
    }

    // MARK: 2. Prepare — put the ring in pairing mode

    private var prepare: some View {
        VStack(spacing: 24) {
            Spacer()
            Image(systemName: "wave.3.right.circle")
                .font(.system(size: 64))
                .foregroundStyle(.tint)
            Text("Put the ring in pairing mode")
                .font(.title2.bold())
                .multilineTextAlignment(.center)
            VStack(alignment: .leading, spacing: 16) {
                step(1, "Place the ring on its charger.")
                step(2, "Take it OFF, then put it back ON the charger.")
                step(3, "Watch for a white blinking light — that's pairing mode.")
                step(4, "Keep the ring near your phone and tap below.")
            }
            Text("Already paired to the Oura app? Factory-reset first: ring on a powered charger, tap the charger on a hard surface ~5–10×.")
                .font(.footnote)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
            Spacer()
            Button {
                page = .running
                ring.startOnboarding()
            } label: { Label("Scan for my ring", systemImage: "dot.radiowaves.left.and.right").frame(maxWidth: .infinity) }
            .buttonStyle(.borderedProminent)
            .controlSize(.large)
            Button("Back") { page = .intro }
                .buttonStyle(.plain)
                .foregroundStyle(.secondary)
        }
    }

    // MARK: 3. Running — live progress, then success / failure

    private var running: some View {
        VStack(spacing: 20) {
            switch ring.onboardingStep {
            case .succeeded(let keyHex):
                successView(keyHex: keyHex)
            case .failed(let reason):
                failureView(reason)
            default:
                progressView
            }
        }
    }

    private var progressView: some View {
        VStack(spacing: 28) {
            Spacer()
            ProgressView().controlSize(.large)
            VStack(spacing: 14) {
                progressRow("Looking for the ring", active: isAtLeast(.scanning), done: isPast(.scanning))
                progressRow("Connecting", active: isAtLeast(.connecting), done: isPast(.connecting))
                progressRow("Claiming the ring with our key", active: isAtLeast(.claiming), done: false)
            }
            Text("Keep the ring close and on the charger (white blink).")
                .font(.footnote).foregroundStyle(.secondary)
            Spacer()
            Button("Cancel") { ring.stop(); page = .prepare }
                .buttonStyle(.plain).foregroundStyle(.secondary)
        }
    }

    private func successView(keyHex: String) -> some View {
        VStack(spacing: 22) {
            Spacer()
            Image(systemName: "checkmark.circle.fill")
                .font(.system(size: 72)).foregroundStyle(.green)
            Text("Ring claimed 🎉").font(.title.bold())
            Text("This phone now owns the ring. The key below is saved on-device. Write it down somewhere safe — it's your only way back if you reinstall the app.")
                .multilineTextAlignment(.center).foregroundStyle(.secondary)
            KeyChip(keyHex: keyHex)
            Spacer()
            Button {
                onComplete()
            } label: { Text("Start reading").frame(maxWidth: .infinity) }
            .buttonStyle(.borderedProminent).controlSize(.large)
        }
    }

    private func failureView(_ reason: OnboardingFailure) -> some View {
        VStack(spacing: 22) {
            Spacer()
            Image(systemName: "exclamationmark.triangle.fill")
                .font(.system(size: 64)).foregroundStyle(.orange)
            Text(reason.title).font(.title2.bold()).multilineTextAlignment(.center)
            Text(reason.detail)
                .multilineTextAlignment(.center).foregroundStyle(.secondary)
            Spacer()
            Button {
                page = .prepare
            } label: { Label("Try again", systemImage: "arrow.clockwise").frame(maxWidth: .infinity) }
            .buttonStyle(.borderedProminent).controlSize(.large)
        }
    }

    // MARK: bits

    private func bullet(_ icon: String, _ text: String) -> some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: icon).frame(width: 24).foregroundStyle(.tint)
            Text(text).font(.subheadline)
            Spacer(minLength: 0)
        }
    }

    private func step(_ n: Int, _ text: String) -> some View {
        HStack(alignment: .top, spacing: 12) {
            Text("\(n)")
                .font(.headline).frame(width: 28, height: 28)
                .background(Circle().fill(.tint.opacity(0.15)))
                .foregroundStyle(.tint)
            Text(text)
            Spacer(minLength: 0)
        }
    }

    private func progressRow(_ label: String, active: Bool, done: Bool) -> some View {
        HStack(spacing: 12) {
            Image(systemName: done ? "checkmark.circle.fill" : (active ? "circle.dashed" : "circle"))
                .foregroundStyle(done ? Color.green : (active ? Color.accentColor : Color.secondary))
            Text(label).foregroundStyle(active || done ? Color.primary : Color.secondary)
            Spacer()
        }
        .font(.subheadline)
    }

    // Ordering helpers so the progress rows light up in sequence.
    private func rank(_ s: OnboardingStep) -> Int {
        switch s {
        case .notStarted: return 0
        case .scanning: return 1
        case .connecting: return 2
        case .claiming: return 3
        case .succeeded: return 4
        case .failed: return -1
        }
    }
    private func isAtLeast(_ s: OnboardingStep) -> Bool { rank(ring.onboardingStep) >= rank(s) }
    private func isPast(_ s: OnboardingStep) -> Bool { rank(ring.onboardingStep) > rank(s) }
}

/// A monospaced key display with copy. Used in onboarding success + the key sheet.
struct KeyChip: View {
    let keyHex: String
    @State private var copied = false
    var body: some View {
        Button {
            UIPasteboard.general.string = keyHex
            copied = true
        } label: {
            HStack {
                Text(keyHex)
                    .font(.system(.footnote, design: .monospaced))
                    .lineLimit(2).truncationMode(.middle)
                Spacer()
                Image(systemName: copied ? "checkmark" : "doc.on.doc")
            }
            .padding()
            .background(Color(.secondarySystemBackground), in: RoundedRectangle(cornerRadius: 10))
        }
        .buttonStyle(.plain)
    }
}
