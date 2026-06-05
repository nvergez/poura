# poura — iOS app

Native iOS port of the macOS `ble-explorer` takeover/read tool. Connects to **your
own** Oura Ring 4 over Bluetooth and reads its biosignals (HR, HRV, temp, accel,
records) directly — no Oura app, no Oura cloud.

## Layout

The protocol core is a **shared package at the repo root**, used by both this app and
the macOS CLI (see the top-level README). The iOS app is just the SwiftUI + CoreBluetooth
layer on top:

```
poura/
├── PouraCore/                 # SHARED SPM package (repo root) — the single source of truth
│   └── Sources/PouraCore/     #   OuraProtocol, Keychain, Hex — no BLE, no UI
├── ble-explorer/              # macOS CLI  → depends on ../PouraCore
└── ios-app/
    ├── PouraApp/PouraApp/     # the iOS app (SwiftUI + CoreBluetooth)
    │   ├── PouraAppApp.swift      # @main entry — routes onboarding vs main
    │   ├── OnboardingView.swift   # first-run pairing (claim) wizard
    │   ├── ContentView.swift      # vitals card, read/auth buttons, diagnostics, key sheet, log
    │   └── RingManager.swift      # CoreBluetooth driver (the iOS BLE state machine)
    └── project.yml            # XcodeGen spec → PouraApp.xcodeproj (depends on ../PouraCore)
```

There is exactly **one** copy of `OuraProtocol`/`Keychain` (in `PouraCore`); the iOS app
and the CLI both depend on it, so a protocol fix lands in both at once.

## Run it on your iPhone

> ⚠️ **Use a real iPhone.** The iOS Simulator has no Bluetooth — `CBCentralManager`
> never reaches `poweredOn`, so nothing connects.

The `.xcodeproj` is generated from `project.yml` (not checked in). Generate + open:

```bash
brew install xcodegen        # one-time
cd ios-app
xcodegen generate            # writes PouraApp.xcodeproj
open PouraApp.xcodeproj
```

Then in Xcode (free personal team / Apple ID sideload):

1. Plug in your iPhone, unlock it, and "Trust This Computer".
2. Select the **PouraApp** target → **Signing & Capabilities** → check
   *Automatically manage signing* → pick your personal **Team** (your Apple ID).
   - The bundle id `com.poura.app` may already be taken on the free tier; if signing
     errors, change it to something unique like `com.<you>.poura`.
3. Pick your iPhone as the run destination → **Run** (⌘R).
4. First launch on a free team: on the phone, **Settings → General → VPN & Device
   Management → trust your developer profile**. Then reopen the app.
   - Free-team apps expire after 7 days; just Run again from Xcode to renew.

> Already generated the project once? Re-run `xcodegen generate` only after editing
> `project.yml` or adding/removing source files. Editing existing `.swift` files needs
> no regeneration.

### Run the core tests (no device needed)

```bash
cd ios-app/PouraCore && swift test
```

## How it works

**First launch → onboarding (pairing) wizard.** With no saved key, the app opens the
onboarding flow:

1. **Intro** — what the app does.
2. **Prepare** — put the ring in *pairing mode*: off the charger → back on → white
   blinking light. (A ring still claimed by the Oura app must be factory-reset first.)
3. **Scan & claim** — the phone generates a **fresh 16-byte key**, finds the ring,
   bonds (Just Works), then `SetAuthKey(our key)` → `GetAuthNonce` → `Authenticate`.
   On the ring's `0x00`, the key is saved to the Keychain. Failure codes are
   translated for you (`0x03` already-claimed → "factory-reset first", etc.).
4. **Success** — shows the key (copyable — back it up) and continues to the main screen.

**Main screen** (once onboarded):

- **Read biosignals**: auth → `SetBleMode/SyncTime/SetNotification` → info queries →
  feature subscribe (0x02) → `data_flush` → `GetEvent(recent cursor)` → live window.
  HR/HRV are computed from the clean IBI beats (0x80/0x60), same maths as the CLI.
- **Test authentication**: reconnect and prove the ring still trusts the saved key.
- **🔑 key sheet**: view/copy the key, or "Forget ring & key" to return to onboarding.

## ⚠️ iOS-specific caveats (read these)

1. **The phone is a separate BLE central from the Mac.** It does NOT inherit the
   Mac's bond or Keychain. The ring trusts a **key**, not a device — which is exactly
   why onboarding claims the ring with its own fresh key. A ring already claimed by
   the Mac (or the Oura app) must be factory-reset before the phone can onboard it.
2. **Rotating BLE address (RPA).** The ring re-randomises its address; the app always
   connects to the freshly-scanned peripheral and never caches the UUID.
3. **Stale bond after a ring reset.** If pairing fails with a pairing/bond error,
   forget the ring under iOS Settings → Bluetooth, then retry. The wizard detects this
   and tells you.
4. **Key sensitivity & backup.** The auth_key is stored
   `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` — not iCloud-synced, gone if you
   delete the app. Losing it does NOT brick the ring (physical reset → re-onboard),
   but **back up the key shown at the end of onboarding** if you want to re-pair
   without resetting. Anyone with the key can read the ring's biosignals.

## Status

Onboarding (pairing) wizard + faithful CoreBluetooth port. **The app builds into a
real `PouraApp.app` for an iOS device** (`xcodebuild … -destination generic/platform=iOS`
→ BUILD SUCCEEDED), `PouraCore` builds for iOS + macOS, and its 11 unit tests pass.

**Not yet run against a physical ring from the phone** — that's the next verification
step once it's signed onto your device. The known open question carried over from the
CLI work (raw PPG `0x81`) is unchanged here; this app reads everything the CLI reads.
