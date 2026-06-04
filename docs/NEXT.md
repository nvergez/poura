# Resume here (handoff note)

Short pointer for picking the project back up in a fresh session. Full story is in
[`JOURNAL.md`](JOURNAL.md); protocol details in [`CAPTURE_ANALYSIS.md`](CAPTURE_ANALYSIS.md).

## Where we are

**Core challenge DONE**: we take over the Oura Ring 4 with our own key, fully
authenticated, zero Oura app/cloud. The ring currently trusts OUR key.

- Tool: `ble-explorer/` (Swift, macOS). Build: `cd ble-explorer && swift build`.
- Modes: `--selftest`, `--oura` (scan+dump), `--takeover`, `--auth [hex]`,
  `--reset [hex]`, `--store-key <hex>`.
- Sanity check the ring still answers: `.build/debug/ble-explorer --auth`
  (loads key from Keychain → expect "PERSISTENCE CONFIRMED").

## Next task: read real data (`--read`)

Add a `--read` mode that: connects (ring NOT in pairing mode is fine for re-auth) →
handshake with the Keychain key → then:
- `GetBatteryLevel` (0x0C), `GetFirmwareVersion` (0x08), `GetProductInfo` (0x18)
- `GetEvent` (0x10) to fetch buffered history by ringTimestamp cursor
- enable real-time stream; decode TLV records:
  `[type:1][len:1][ctr_lo][ctr_hi][ses_lo][ses_hi][payload]`,
  `ringTimestamp=(session<<16)|counter`. Notable types: 0x33 accel, 0x42 time
  anchor, 0x80 IBI quality, 0x81 raw PPG, 0x85 RTC beacon.
- For physiological data, the ring must be WORN (on finger), not on the charger.

Frame builders + AES proof already exist in `OuraProtocol.swift`. GATT: write =
`98ED0002` (handle 0x0015), notify = `98ED0003` (handle 0x0012), service `98ED0001`.

## Gotchas to remember

- **Pairing mode** (only needed for first takeover after a reset): remove ring from
  charger + put back → white blinking light → connection window opens.
- **"Peer removed pairing information"** on connect = stale Mac BLE bond after a
  ring reset → forget the ring in System Settings → Bluetooth, then retry.
- Ring uses a **rotating BLE address** (RPA); always connect to the freshly-scanned
  peripheral, don't cache the UUID.
- Git: `origin` uses **HTTPS + gh credential helper** (no SSH key on this Mac).
