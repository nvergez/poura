# Resume here (handoff note)

Short pointer for picking the project back up in a fresh session. Full story is in
[`JOURNAL.md`](JOURNAL.md); protocol details in [`CAPTURE_ANALYSIS.md`](CAPTURE_ANALYSIS.md).

## Where we are

**Core challenge DONE** + **data retrieval working** (infos + records + live AFE
stream). We take over the Oura Ring 4 with our own key (zero Oura app/cloud), and
`--read` pulls infos, decodes the TLV record stream/history, AND triggers a live
data stream from the worn ring. The ring currently trusts OUR key.

- Tool: `ble-explorer/` (Swift, macOS). Build: `cd ble-explorer && swift build`.
- Modes: `--selftest`, `--oura`, `--takeover`, `--auth [hex]`,
  `--read [hex] [--history] [--seconds N] [--features 02,03,…]`, `--reset [hex]`,
  `--store-key <hex>`.
- Sanity check: `.build/debug/ble-explorer --auth` (expect "PERSISTENCE CONFIRMED").
- Read everything: `.build/debug/ble-explorer --read --history --seconds 30`.

### What `--read` already does (verified, see JOURNAL 2026-06-05 + 2026-06-05b)
- Infos: battery 96%, firmware 2.0.0.2.11, product `ORE_06` / serial
  `2016092441019131`. Resp tag = req opcode+1 (`0x09/0x0d/0x19`).
- Post-auth init: `SetBleMode 16 01 02` → `SyncTime` → `SetNotification 1c 01 bf`.
- **Feature subscribe = measurement trigger**: `2f 03 22 02 03` (set) +
  `2f 03 26 02 02` (subscribe) → ring ACKs `2f 03 27 02 00` and starts streaming.
- `data_flush 28 01 00` drains the flash buffer (only flushes what's buffered).
- **Live AFE stream** (worn ring): `2f 0f 28 02 <chan> 02 00 00 <value u16 LE> …`,
  chan 0x09 ≈ 5150 (likely PPG DC level), ~0.5–1 Hz.
- History: `GetEvent 10 09 <cursor u32 LE> <max u8> <flags=FFFFFFFF>`.
- TLV decode validated: `[type][len][ctr u16][ses u16][payload]`. Decoded 0x41 boot,
  0x42 time-anchor (unix ts), 0x43 ASCII diag, 0x61 events. Decoders ready for
  0x46 temp + 0x80 IBI-quality (not yet seen live).

## ✅ SOLVED: biosignals come from GetEvent with a RECENT cursor (not the live stream)

`--read --cursor recent` retrieves real worn-ring records: IBI (0x80/0x60), temp
(0x46, decoded ✅), motion (0x47). The earlier "feature subscribe stream" only gives
a slow AFE channel; the actual PPG/IBI data is in the flash event log and you fetch
it with `GetEvent` from a cursor near the ring's CURRENT ringTimestamp (cursor 0 only
replays the old boot/charge log). `--cursor recent` reads ring-now from the SyncTime
ack and fetches from there.

## Next task: decode IBI/PPG payloads + capture 0x81

- **0x80 IBI packing** is NOT validated — bits-0..10 give incoherent ms. Currently
  printed as raw u16 words. Validate against a known heart rate (count your pulse for
  15 s during a run) or open_ring `decoders.py` L417/L646. Same for 0x60.
- **0x81 raw PPG** (delta-encoded) didn't appear in a short window — do a longer
  `--read --cursor recent --seconds 30` (or a couple of runs) to catch it, then write
  the stateful delta decoder (0x80 marker → 3-byte abs u24; MSB-set = signed delta).
- Optional older leads (the live-stream path, lower priority now):
  Feature 0x02 streams only a slow AFE channel (~1 Hz). Probed features
  0x02/03/04/0b/0d/10 — all ACK subscribe, only 0x02 emits. If you revisit:
- **Scheduled measurement hypothesis**: the ring may only run high-rate PPG during
  sleep / spot-check sessions, not over an active BLE link (power). Try: subscribe,
  then **disconnect and let the ring measure**, reconnect later and `--history` to
  pull the buffered 0x80/0x81 records. Or keep the ring worn + still for a long
  window and watch for a session to start.
- **Other subscribe values**: we always send `subscribe <id>=0x02`. The app also
  used `set 0x02=0x03`. Try other set/subscribe VALUES (not just IDs) — e.g.
  `featureSubscribe(0x02, 0x01/0x03/…)`. Decode more of frames 1154+ in the
  onboarding capture (`SetUserInfo 0x20 …`) — a user/measurement-config write may
  be the precondition.
- **Unused chars**: `98ED0004` (read/write/notify/indicate), `98ED0005/0006`
  (notify-only) may be separate high-rate data channels. We only enable notify on
  `98ED0003`. Try enabling notify on 0004/0005/0006 too.
- When 0x81 appears: it's **delta-encoded and stateful** (0x80 marker → 3-byte abs
  u24 reset; MSB-set byte = signed delta; else 7-bit signed delta). 0x80 IBI is
  already decoded (`decodeBiosignal`). Use 0x42 anchor for wall-clock.

Frame builders + AES proof + TLV/biosignal decoders live in `OuraProtocol.swift`;
read sequence + `handleReadNotification` (info / live-stream / TLV) in `main.swift`.
GATT: write = `98ED0002` (0x0015), notify = `98ED0003` (0x0012), service `98ED0001`.
Decoded onboarding capture: `~/.superset/projects/poura/captures/poura-onboarding.btsnoop`
(tshark) — re-mine frames 1000-1300 for the measurement-session records.

## Gotchas to remember

- **Pairing mode** (only needed for first takeover after a reset): remove ring from
  charger + put back → white blinking light → connection window opens.
- **"Peer removed pairing information"** on connect = stale Mac BLE bond after a
  ring reset → forget the ring in System Settings → Bluetooth, then retry.
- Ring uses a **rotating BLE address** (RPA); always connect to the freshly-scanned
  peripheral, don't cache the UUID.
- Git: `origin` uses **HTTPS + gh credential helper** (no SSH key on this Mac).
