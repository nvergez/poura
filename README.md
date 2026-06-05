# poura

Reverse engineering the **Oura Ring 4** to connect to it over BLE and read its
data **without going through the Oura app or Oura's servers**.

> Ring purchased and owned 100% by the author. RE for interoperability and
> personal-use purposes (legal in France/EU — art. L122-6-1 CPI). No
> redistribution of Oura firmware, no circumvention of Oura's servers for
> commercial purposes.

## Status

🟢 **Core challenge ACHIEVED** — we take over the ring with OUR own key, fully
authenticated, **zero Oura app/cloud** in the auth path.
🟢 **Data + biosignals retrieved** — `--read` pulls device infos, decodes the TLV
record stream/history, and `--read --cursor recent` retrieves **real physiological
records from the worn ring**: IBI/heart-beat (0x80/0x60), temperature (0x46,
decoded: ~25.8°C skin), motion (0x47). All without the Oura app. Remaining: validate
IBI bit-packing + capture raw PPG (0x81), then iOS app.

## Goals

### Core challenge — ✅ DONE
**Pair with the ring and authenticate without the official Oura app, from scratch.**
Achieved: after a factory reset, our macOS tool sets its own `auth_key` on the ring
and authenticates. The official Oura app can no longer reclaim the ring (it enters
"restricted mode") until a factory reset — proving the takeover holds.

### Data retrieval — ✅ DONE (infos + records); biosignals in progress
`--read` (saved-key handshake → read) verified on the real ring:
- **Battery 96%**, **firmware 2.0.0.2.11**, **product** `ORE_06` / serial
  `2016092441019131` — all read directly, no Oura app.
- **TLV records decoded** (~256 in one history dump): boot (`0x41`), time-anchor
  (`0x42`, unix ts), **ASCII diag logs** (`0x43`: `git;…`, `HWID;ORE_06`,
  `acm_bma456`…), events (`0x61`). Decoder validated on our own data.
- **Live AFE stream** from the worn ring via feature subscribe (`2f 03 26 02 02`):
  channel 0x09 value ≈ 5150 (likely PPG DC level), reacts to finger movement.
- ⏳ **High-rate PPG waveform** (`0x81`) + **IBI** (`0x80`) not yet streamed — only
  feature 0x02 emits, and it's the slow AFE channel. Likely needs a scheduled
  measurement session. See `docs/NEXT.md`.

### Next
- Capture raw biosignals (wear ring, investigate measurement-start). 
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
.build/debug/ble-explorer --read [hexkey]      # auth → infos → subscribe feat 0x02 → live AFE stream
.build/debug/ble-explorer --read --history     # also dump buffered flash history (GetEvent)
.build/debug/ble-explorer --read --seconds 30  # keep the live-stream window open for 30s
.build/debug/ble-explorer --read --cursor recent      # fetch RECENT records → IBI/temp/motion biosignals
.build/debug/ble-explorer --read --features 02,03,0b  # probe other feature IDs for PPG/IBI
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
