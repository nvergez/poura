# poura

Reverse engineering the **Oura Ring 4** to connect to it over BLE and read its
data **without going through the Oura app or Oura's servers**.

> Ring purchased and owned 100% by the author. RE for interoperability and
> personal-use purposes (legal in France/EU — art. L122-6-1 CPI). No
> redistribution of Oura firmware, no circumvention of Oura's servers for
> commercial purposes.


## Status

🟢 **Core challenge ACHIEVED** — we take over the ring with OUR own key, fully
authenticated, **zero Oura app/cloud** in the auth path. Next: reading data + iOS app.

## Goals

### Current goal (the challenge) — ✅ DONE
**Pair with the ring and authenticate without the official Oura app, from scratch.**
Achieved: after a factory reset, our macOS tool sets its own `auth_key` on the ring
and authenticates. The official Oura app can no longer reclaim the ring (it enters
"restricted mode") until a factory reset — proving the takeover holds.

### Next
- Read real data over BLE (battery, firmware, then HR/IBI/temp/accel/PPG records).
- Port to a native iOS app (Swift / CoreBluetooth), reusing `OuraProtocol.swift`.
  Clean-room: `open_ring`/`ringverse` used only as reference docs, not as a codebase.

## What we established (verified on the real ring)

- **auth_key is generated LOCALLY** by the phone (random), NOT server-side — so a
  factory-reset ring accepts a fresh `SetAuthKey` (0x24) with no server validation.
  The "wall" was never crypto; it was a protocol/state question.
- **Takeover sequence** (after factory reset, ring in **pairing mode** = remove
  from charger + put back → white blinking light): connect → BLE bond (Just Works)
  → `SetAuthKey(our 16B key)` → `GetAuthNonce` → `Authenticate` with
  `proof = AES-128-ECB(key, nonce15 ‖ 0x01)` → ring returns `0x00`.
- **GATT**: service `98ED0001…`; write commands → `98ED0002` (handle 0x0015),
  responses notify on `98ED0003` (handle 0x0012).
- You only get **raw biosignals** (PPG, IBI, accel, temp, battery) — not the
  sleep/readiness scores (those are computed in the Oura cloud).
- Ring identity: hardware "ORE_06" / codename **oreo** (a Ring 4 variant).

Full details: [`docs/CAPTURE_ANALYSIS.md`](docs/CAPTURE_ANALYSIS.md),
[`docs/JOURNAL.md`](docs/JOURNAL.md), [`docs/PROTOCOL.md`](docs/PROTOCOL.md).

## BLE explorer — usage

```bash
cd ble-explorer && swift build
.build/debug/ble-explorer --selftest          # validate AES-128-ECB (no BLE)
.build/debug/ble-explorer                      # scan & list nearby BLE devices
.build/debug/ble-explorer --oura               # find + connect the ring, dump GATT
.build/debug/ble-explorer --takeover           # set OUR key on a FACTORY-RESET ring (pairing mode)
.build/debug/ble-explorer --auth [hexkey]      # authenticate (key from arg or Keychain)
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
docs/          Documentation: strategy, protocol, investigation journal
research/      RE notes (APK analysis, decoded captures)
captures/      btsnoop captures / raw BLE logs (git-ignored if large/sensitive)
ble-explorer/  BLE exploration tool (macOS/CLI) — scan, connect, dump GATT
ios-app/       The final iOS app (Swift)
```

## Reproduce the takeover (quick start)

1. Factory-reset the ring (Oura app → ring icon → Factory Reset; or physical reset).
   Do **not** complete a new Oura onboarding afterward.
2. Put the ring in **pairing mode**: remove from charger, put back → white blinking.
3. `cd ble-explorer && swift build && .build/debug/ble-explorer --takeover`
4. On success the ring trusts our key (stored in Keychain). `--auth` re-authenticates
   anytime. The Oura app can reclaim it only after another factory reset.
