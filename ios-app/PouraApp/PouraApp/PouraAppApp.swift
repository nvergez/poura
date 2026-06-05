import SwiftUI
import PouraCore

@main
struct PouraAppApp: App {
    @StateObject private var ring = RingManager()
    // Onboarded once a 16-byte key is in the Keychain. Checked at launch; flipped by
    // the onboarding wizard on success (or if the user deletes the key in settings).
    @State private var onboarded = Keychain.loadAuthKey()?.count == 16

    var body: some Scene {
        WindowGroup {
            Group {
                if onboarded {
                    ContentView(onSignedOut: { onboarded = false })
                } else {
                    OnboardingView(onComplete: { onboarded = true })
                }
            }
            .environmentObject(ring)
        }
    }
}
