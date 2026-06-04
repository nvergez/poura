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

Hybrid **streaming + batch catch-up**:

- **Live**: records as notifications, bursts ≤247 B/ATT value, latency ≤~300 ms.
- **Batch history**: on reconnect, `GetEvent (0x10 → 0x11)` retrieves the flash
  history by `ringTimestamp` cursor. Ack-fetch (`max_events=0`) advances the cursor
  without data. Each sync emits `data_flush (0x28)` first.
- **Outer frame**: `[op:1][len:1][body]`.
- **Inner records (TLV)**:
  `[type:1][len:1][ctr_lo][ctr_hi][ses_lo][ses_hi][payload]`
  with `ringTimestamp = (session<<16)|counter` (two LE u16).
- **~40–50 record types** decoded. Notable ones:

| Type | Content |
|------|---------|
| `0x33` | accelerometer |
| `0x41` | ring boot/start |
| `0x42` | time-sync anchor (`API_TIME_SYNC_IND`) |
| `0x45` | state change |
| `0x80` | green-LED IBI quality |
| `0x81` | raw PPG (delta-encoded, stateful across reconnections) |
| `0x85` | RTC beacon |

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
