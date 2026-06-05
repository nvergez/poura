# Oura Ring 4 protocol — reference notes

> Synthesis of the initial research (sources: `LogosIsLife/open_ring`,
> `ringverse/protocol`, FCC, teardowns). **Everything is to be re-validated against
> our own captures.** Confirmed for **Ring 4 only**; the Gen3 is not publicly
> documented.

## Sources

| Source | URL | Content |
|--------|-----|---------|
| open_ring | https://github.com/LogosIsLife/open_ring | Most complete clean-room Python toolkit (driver + spec + ~953K captured records). `master` branch, `PROTOCOL.md`. |
| ringverse/protocol | https://github.com/ringverse/protocol | Protocol docs: `oura/BLE.md`, `oura/data.md`, `oura/storage.md`. GATT, opcodes, handshake, key storage. |
| FCC filing | https://fccid.io/2AD7V-OURA1801 | HW: Cypress/Infineon PSoC 6 BLE MCU. |
| Pen Test Partners | https://www.pentestpartners.com/security-blog/reverse-engineering-ble-from-android-apps-with-frida/ | BLE RE methodology via Frida. |
| Gadgetbridge wiki | https://codeberg.org/Freeyourgadget/Gadgetbridge/wiki/BT-Protocol-Reverse-Engineering | BT protocol RE methodology. |

⚠️ open_ring = single repo, few stars, some fields asserted by a single author.
The two repos **diverge on the AES mode** (ringverse prose says "CBC/PKCS5", but
the code and open_ring confirm **ECB**). We validate everything.

## GATT (Ring 4)

- **Service**: `98ed0001-a541-11e4-b6a0-0002a5d5c51b`
- **Notify char**: `98ed0003-a541-11e4-b6a0-0002a5d5c51b` — handle `0x0012`,
  ATT op `0x1B` (Handle Value Notification)
- **Write char**: handle `0x0015`, write-without-response (ATT op `0x12`).
  UUID not cited in the docs (handle only).
- **ATT**: channel `0x0004`, little-endian.
- **MTU**: notifications up to 247 bytes. Explicit Exchange MTU required
  (default 23 bytes otherwise → fragmentation/loss of long records).

### Confidentiality
No AEAD/MAC on the application payloads. Confidentiality rests **entirely** on the
BLE link-layer encryption (bonding LTK). Passive sniffer without the LTK = opaque
encrypted traffic; bonded client = cleartext payloads.

## Authentication handshake

Over the bonded link:

| Opcode | Name | Detail |
|--------|------|--------|
| `0x24` | Set Auth Key | **16-byte** key unique to the ring |
| `0x2B` → `0x2C` | Get Auth Nonce | ring returns a **15-byte** nonce |
| `0x2D` | Authenticate | submits the 16-byte `proof` |

```
proof = AES_128_ECB(auth_key, nonce ‖ 0x01)[:16]
       (plaintext = 15-byte nonce + 0x01 = 1 block of 16; ECB mode)
```

`0x2D` return codes:
- `0x00` success
- `0x01` auth error
- `0x02` in factory reset
- `0x03` **not the original onboarded device** ← the wall

### auth_key provenance (THE investigation point)
Not derivable on-device per the public record; read from the app's storage after
onboarding:
- **iOS**: `assa.sqlite`, table `ringconfiguration` →
  `SELECT id, auth_key FROM ringconfiguration` (extracted from an iTunes backup).
- **Android**: `assa-store.realm` (Realm DB) — extraction details "TODO".

→ See `docs/STRATEGY.md`: determining whether the key is derived from a ring
secret (a) or pure server randomness (b) is the project's go/no-go.

## Data sync model

Hybrid **streaming + batch catch-up**. ✅ **Verified on our ring** via `--read`
(see JOURNAL 2026-06-05): infos + ~256 TLV records decoded, no Oura app.

- **Post-auth init (replayed from capture, our ring acks each):**
  `SetBleMode 16 01 02` → `SyncTime 12 09 <unix LE> 00000000 04`
  → `SetNotification 1c 01 bf`. Ack tags = req opcode+1 (`17`,`13`,`1d`).
- **`data_flush` (0x28 01 00)** drains the flash buffer onto the notify stream
  (`SetNotification` alone stays silent). But it only flushes what's ALREADY
  buffered — it does not start measurement.
- **Measurement trigger = feature SUBSCRIBE (ext 0x2F).** ✅ Verified on a worn
  ring. The app runs a get/set/subscribe block before data_flush:
  ```
  get:        2f 02 20 <id>       → 2f 06 21 <id> <4B value>
  set:        2f 03 22 <id> <val> → 2f 03 23 <id> <val>   (ack)
  subscribe:  2f 03 26 <id> <val> → 2f 03 27 <id> <code>  (ack)  ← starts the stream
  ```
  Decisive pair: `2f 03 22 02 03` (set feat 0x02=3) then `2f 03 26 02 02`
  (subscribe feat 0x02=2). On a worn ring this opens a **live AFE data stream**:
  ```
  2f 0f 28 02 <chan> 02 00 00 <value u16 LE> 00 00 00 00 59 0a 7f
  chan ∈ {0x09,0x19}; value ≈ 5150 ±60 at rest (likely PPG DC level), ~0.5–1 Hz.
  ```
  ⚠️ Features 0x03/0x04/0x0b/0x0d/0x10 all ACK subscribe but only **0x02** emits
  data (a slow ~1 Hz AFE channel).
- **✅ Biosignals come from `GetEvent` with a RECENT cursor, not the live stream.**
  The app's PPG/IBI/temp records (capture: 0x81×108, 0x80×47, 0x60×41, 0x46×90)
  arrived as the response to `GetEvent` with a cursor near the ring's CURRENT
  ringTimestamp (`10 09 <recent cursor> 00 ffffffff`). Cursor 0 only replays the
  old boot/charge log. Our `--read --cursor recent` reads ring-now from the SyncTime
  ack and fetches recent records → on the worn ring this returns IBI (0x80/0x60),
  temp (0x46, decoded `[25.8, 28.0, 21.4]°C`), motion (0x47). IBI bit-packing +
  0x81 PPG delta decode still TODO.
- **Live**: records as notifications, bursts ≤247 B/ATT value, latency ≤~300 ms.
- **Batch history**: `GetEvent (0x10 → 0x11)` retrieves flash history by
  `ringTimestamp` cursor. **Wire format (11 B, verified):**
  `10 09 <cursor u32 LE> <max_events u8> <flags u32 LE = FFFFFFFF>`.
  `cursor=0` = full dump; `max_events=0` = ack-only (advance cursor without data).
- **Simple infos (req → resp tag = req opcode+1):** `GetFirmwareVersion 08 03 000000`
  → `09…`; `GetBatteryLevel 0c 00` → `0d 06 <pct> …` (`0x60`=96%);
  `GetProductInfo 18 03 <sub> 00 10` → `19 11 00 <ASCII>` (`ORE_06`, serial, …).
- **Outer frame**: `[op:1][len:1][body]`.
- **Inner records (TLV)** — ✅ decoder validated on our dump:
  `[type:1][len:1][ctr_lo][ctr_hi][ses_lo][ses_hi][payload(len-4)]`
  with `ringTimestamp = (session<<16)|counter` (two LE u16). `len` covers the 4
  timestamp bytes + payload; consume `2+len` per record.
- **~40–50 record types** total. ✅ = decoded & verified on OUR ring's data:

| Type | Content (decoded values where ✅) |
|------|------------------------------------|
| `0x33` | accelerometer (sensor = Bosch **BMA456**, per `0x43` diag log) |
| `0x41` | ✅ ring boot/start (`… 32 02 0b …` = fw at boot) |
| `0x42` | ✅ time-sync anchor — payload = unix ts LE |
| `0x43` | ✅ **diag-log ASCII** (`git;…`, `HWID;ORE_06`, `acm_bma456`, `chgv;…`) |
| `0x45` | ✅ state-change: byte0 flag + ASCII name (`hr enable`, `motion det`…) |
| `0x46` | ✅ **temperature** 3× i16 LE /100 °C (`[25.8, 28.0, 21.4]`) |
| `0x47` | ✅ **3-axis accelerometer** int8×8 (`accel=(-816,-328,136)`) |
| `0x50` | ✅ activity-info (byte0 class; bins opaque) |
| `0x5b` | ✅ ble-conn telemetry (sub-dispatch; fields inferred) |
| `0x5d` | ✅ **HRV** N×(HR bpm, RMSSD ms)/5-min |
| `0x60` | ✅ **IBI+amplitude** (heart beats) |
| `0x61` | ✅ **debug-data** sub-dispatch (battery/fuel/sleep/ble/flash/PPG-quality; AFE chip = Maxim **MAX86178**) |
| `0x6b` | ✅ motion-period (NO_MOTION/RESTLESS/TOSSING/ACTIVE, low 2 bits) |
| `0x6c` | ✅ feature-session (feature/capability/status) |
| `0x72` | ✅ sleep-acm 6× u16 LE metrics |
| `0x75` | ✅ sleep-temp N× i16 LE /100 °C trace |
| `0x80` | ✅ **green-LED IBI quality** → HR/HRV (`ibi=(b_lo<<3)|(b_hi&7)` ms) |
| `0x81` | ⏳ raw PPG (delta-encoded, stateful) — see note |
| `0x82`/`0x83` | ✅ scan-start / scan-end |
| `0x85` | RTC beacon (unix ts LE u32 + trailer) |

> **0x81 raw PPG** is the only signal not retrieved from our ring: it is NOT in the
> retrievable event log (the ring derives IBI on-device and discards the raw
> waveform). The app capture caught 0x81 live during an active measurement burst
> (session 5392). Everything that derives from PPG — HR, HRV, IBI — already works.
> Heart rate cross-validated vs the user's Fitbit (60–67 bpm).

- **Time**: ticks (~100 ms/tick default, 1 ms in burst), → UTC via `0x42`
  anchors. open_ring: `RingTimeResolver` (RE of `libappecore.so`).
- **Output**: you get raw biosignals (IBI, PPG, accel, temp, battery), **not** the
  sleep/readiness scores (cloud).

## RE tools (used by the community)

- **Native disasm** of the APK's `.so` files: `libringeventparser.so`,
  `libappecore.so` via `llvm-objdump` (LLVM 14+). open_ring:
  `tools/extract_wireformat.py`.
- **btsnoop HCI** (Android → Dev options → "Enable Bluetooth HCI snoop log")
  analyzed in **Wireshark** (~953K records).
- **On-device ground truth**: dump Realm (`assa-store.realm`) + SQLite
  (`assa.sqlite`). open_ring: `verify_claims.py`.
- **ADB + root**: pull `bt_config.conf` (BLE bond) and the Realm DB.
- **BlueZ** (Linux) + Python `bleak`/`cryptography` as runtime.
- Standard tools: **Frida, jadx, dex2jar, nRF Connect** (general methodology;
  open_ring mostly did static + captures, no runtime hooking credited).

## Gen3 vs Gen4

The **Gen3** BLE protocol is NOT publicly documented. All the detailed RE targets
the Ring 4. Plausible but **unverified** that Gen3 shares the `98ed00xx` service /
the handshake / the TLV format. Do not assume it transfers.
