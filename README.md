# poura

Reverse engineering the **Oura Ring 4** to connect to it over BLE and read its
biosignals **without going through the Oura app or Oura's servers**.

A community, open-source RE project. It ships **two apps** that talk to the ring
directly: a **macOS CLI** (`ble-explorer`) for exploration, and a **native iOS app**
(SwiftUI + CoreBluetooth). Both sit on top of a single shared Swift package
(`PouraCore`) that holds the protocol — so a fix lands in both at once.

> For interoperability and personal-use purposes only. You should only run this
> against a ring **you own**. Reverse engineering for interoperability is legal in
> the EU (art. L122-6-1 CPI in France). No redistribution of Oura firmware, no
> circumvention of Oura's servers for commercial purposes.

## Status

🟢 **Takeover works** — you can claim a factory-reset ring with **your own** key,
fully authenticated, with **zero Oura app/cloud** in the auth path. Once claimed,
the official Oura app can no longer reclaim the ring (it goes into "restricted
mode") until a factory reset — proving the takeover holds.

🟢 **Biosignal read works** — the CLI authenticates with the saved key and reads
real biosignals straight from the ring, no Oura app: **heart rate + HRV (RMSSD)**,
**skin temperature**, **3-axis accelerometer**, **IBI**, **motion state**, plus
full device telemetry (battery, firmware, fuel gauge, sensor IDs, BLE/flash stats).
~17 record types decoded.

🟢 **iOS app** — a native SwiftUI + CoreBluetooth app that ports the takeover +
read flow to the phone: a first-run pairing (claim) wizard, then a main screen that
reads the same biosignals as the CLI. It builds into a real `.app` for an iOS
device and `PouraCore`'s unit tests pass.

⚠️ **One known boundary** — the raw PPG waveform (`0x81`) is the only signal this
ring/firmware does not expose over BLE. The ring derives IBI on-device and discards
the raw optical samples, so they never appear in the BLE event log. This is a
capability boundary, not a decode gap — every derived physiological signal
(HR / HRV / IBI) already works.

## What this proves (verified on a real ring)

- **The `auth_key` is generated LOCALLY** by the phone (random), NOT server-side —
  so a factory-reset ring accepts a fresh `SetAuthKey` (0x24) with no server
  validation. The "wall" was never crypto; it was a protocol/state question.
- **Takeover sequence** (after factory reset, ring in **pairing mode** = remove
  from charger + put back → white blinking light): connect → BLE bond (Just Works)
  → `SetAuthKey(your 16B key)` → `GetAuthNonce` → `Authenticate` with
  `proof = AES-128-ECB(key, nonce15 ‖ 0x01)` → ring returns `0x00`.
- **GATT**: service `98ED0001…`; write commands → `98ED0002` (handle 0x0015),
  responses notify on `98ED0003` (handle 0x0012).
- You get **raw biosignals** (PPG-derived HR/HRV/IBI, accel, temp, battery) — but
  **not** the sleep/readiness scores (those are computed in the Oura cloud).
- The ring trusts a **key, not a device** — which is why each central (Mac, phone)
  claims the ring with its own fresh key.

Full details: [`docs/CAPTURE_ANALYSIS.md`](docs/CAPTURE_ANALYSIS.md),
[`docs/JOURNAL.md`](docs/JOURNAL.md), [`docs/PROTOCOL.md`](docs/PROTOCOL.md).

## What's next

- Decode the raw PPG waveform (`0x81`) if a path to a full optical trace exists.
- Run the iOS app against a physical ring end-to-end from the phone (the CLI flow
  is already verified; the iOS port is the remaining hands-on validation step).

## The two apps

### iOS app — `ios-app/`

Native SwiftUI + CoreBluetooth. First launch opens a pairing wizard that generates
a fresh 16-byte key, finds the ring, bonds, and claims it; the key is saved to the
iOS Keychain. The main screen then reads biosignals and can re-authenticate.
See [`ios-app/README.md`](ios-app/README.md) for the full run-on-device guide.

### macOS CLI — `ble-explorer/`

```bash
cd ble-explorer && swift build
.build/debug/ble-explorer --selftest          # validate AES-128-ECB (no BLE)
.build/debug/ble-explorer                      # scan & list nearby BLE devices
.build/debug/ble-explorer --oura               # find + connect the ring, dump GATT
.build/debug/ble-explorer --takeover           # set YOUR key on a FACTORY-RESET ring (pairing mode)
.build/debug/ble-explorer --auth [hexkey]      # authenticate (key from arg or Keychain)
.build/debug/ble-explorer --firmware [hexkey]  # authenticate then READ firmware version + product info (no writes)
.build/debug/ble-explorer --read [hexkey]      # auth → infos → subscribe feat 0x02 → live AFE stream
.build/debug/ble-explorer --read --history     # also dump buffered flash history (GetEvent)
.build/debug/ble-explorer --read --seconds 30  # keep the live-stream window open for 30s
.build/debug/ble-explorer --read --cursor recent      # fetch RECENT records → HR/HRV/temp/accel biosignals
.build/debug/ble-explorer --read --drain --seconds 60 # repeated GetEvent (drain records as the ring measures)
.build/debug/ble-explorer --read --burst --seconds 50 # keep DHR HR-burst engaged (attempt raw PPG 0x81)
.build/debug/ble-explorer --read --features 02,03,0b  # probe other feature IDs
.build/debug/ble-explorer --reset [hexkey]     # authenticate then factory-reset (give ring back)
.build/debug/ble-explorer --store-key <hexkey> # save a key into the macOS Keychain
```

The auth_key is stored in the **macOS Keychain** (`--takeover` auto-stores it).
If a re-takeover fails with "Peer removed pairing information", forget the ring in
System Settings → Bluetooth (stale bond) and retry.

⚠️ **Key loss**: if the key is lost, the ring is NOT bricked — do a physical reset
(ring on powered charger, tap charger on a hard surface ~5-10×) then re-takeover.

## Hardware setup

- **Mac**: dev (Xcode; CoreBluetooth is also available on macOS for exploration).
- **Physical iPhone**: real BLE (the iOS simulator has no Bluetooth).
- **Android**: BLE sniffing via HCI snoop log (btsnoop) — much simpler than iOS.

## Directory layout

```
PouraCore/     Shared Swift package — the protocol core (no BLE, no UI)
ble-explorer/  macOS CLI — scan, connect, dump GATT, takeover, read
ios-app/       Native iOS app (SwiftUI + CoreBluetooth)
docs/          Documentation: strategy, protocol, investigation journal
research/      RE notes (APK analysis, decoded captures)
captures/      btsnoop captures / raw BLE logs (git-ignored if large/sensitive)
```

## Reproduce the takeover (quick start)

1. Factory-reset the ring (Oura app → ring icon → Factory Reset; or physical reset).
   Do **not** complete a new Oura onboarding afterward.
2. Put the ring in **pairing mode**: remove from charger, put back → white blinking.
3. `cd ble-explorer && swift build && .build/debug/ble-explorer --takeover`
4. On success the ring trusts your key (stored in Keychain). `--auth` re-authenticates
   anytime. The Oura app can reclaim it only after another factory reset.
