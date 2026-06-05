# Investigation journal

Dated notes throughout the RE. Hypotheses, tests, results, dead-ends.

---

## 2026-06-04 — Phase 0: Recon

- Project initialized (empty). Setup: Mac + iPhone + Android. Ring = **Oura Ring 4**.
- Research: the Ring 4 BLE protocol is already publicly RE'd (`open_ring`,
  `ringverse`). See `docs/PROTOCOL.md`.
- **Decision**: current goal = pair with the ring **without the Oura app** (from
  scratch, in Swift, clean-room). Long-term goal (standalone app after onboarding
  once) documented for later.
- **Wall identified**: 16-byte `auth_key` handshake, code `0x03` if not onboarded.
- **Next pivot**: investigate the origin of the `auth_key` (ring-derived vs server
  randomness) = go/no-go. See `docs/STRATEGY.md`.

### Don't forget
- ⚠️ DO NOT reset the ring before sniffing the official onboarding.

### Open questions
- Is the BLE bond (problem A) acceptable to a reset ring from an arbitrary central?
- Is the `98ed00xx` service actually exposed by our ring (to confirm via GATT dump)?

---

## 2026-06-04 — auth_key origin investigation (go/no-go)

**Verdict: publicly unknown, the evidence leans toward the pessimistic (b), BUT
the decisive experiment has never been published and we have the hardware to run
it.**

- `open_ring` & `ringverse` treat the auth_key as **opaque**: they EXTRACT it from
  the phone (`assa-store.realm` / `assa.sqlite` table `ringconfiguration`), they
  never compute it. `open_ring` asks the user to supply their own `.realm` → if
  they knew how to derive it, they'd automate it. Strong signal toward (b).
- No public analysis of the onboarding traffic says whether the key transits over
  the network. **That is precisely the missing experiment.**
- In `assa-store.realm`: the auth_key follows the marker `41 41 41 41 11 00 00 10`
  (16 bytes right after). Extracted by linear scan.
- Handshake validated: `proof = AES_128_ECB(auth_key, nonce‖0x01‖PKCS5)[:16]`
  (484/484 nonce/proof pairs in open_ring). ECB is the reliable formulation.

### → THE DECISIVE EXPERIMENT (the project's go/no-go)
During a live official onboarding, determine the origin of the auth_key's 16 bytes:
1. **Frida hook** on the auth_key write into the Realm → inspect inputs + call
   stack: do they come from an HTTP response buffer (→ b) or from a local
   computation over the ring's serial/MAC (→ a)?
2. **HTTPS MITM** (mitmproxy/Burp + custom CA + Frida unpinning) on the device
   registration endpoint → are the 16 bytes in a server response?

If bytes ∈ server response → (b) → pivot to the long-term goal (onboard once,
extract the key, standalone app). Otherwise → (a) → the real zero-Oura challenge
is on.

### APK RE method (for the record)
- APK: `adb shell pm path com.ouraring.oura` then `adb pull` (or APKMirror).
- Java/Kotlin: jadx-gui. Grep: `auth_key`, `authKey`, `ringConfiguration`,
  `assa-store`, Retrofit toward `cloud.ouraring.com`/`api.ouraring.com`.
- Native: Ghidra/IDA on `libappecore.so`, `libringeventparser.so`. Symbols:
  `setAuthKey`, `Authenticate`, `nonce`, `derive`, `HKDF`, `AES`.
- Decisive test: where is the auth_key **first assigned**? HTTP response (b) vs
  local function (a).

### Ethics noted
MITM + Frida on the Oura app = on HIS ring, HIS phone, HIS data, personal interop.
Legitimate. No redistribution, no third-party targeting.

---

## 2026-06-04 — Android Seeker setup + APK retrieval

- **Device**: Solana Mobile **Seeker** (`seeker_eea`), **Android 15** (SDK 35).
  USB debugging OK, authorized. adb sees the device.
- **Oura app already installed** (not onboarded on the Android side):
  `com.ouraring.oura` **v7.16.0** (versionCode 260527103, targetSdk 36). Split APK
  (6 pieces). → APK pulled into `captures/oura-apk/` (git-ignored).
- **Found `split_ring_firmware.apk`** — Oura's internal ring codenames: `gen2`,
  `gen2x`, `cooper`, `nomad`, `nomad2`, `oreo`. Firmwares in `.cyacd2` format =
  **Cypress/Infineon PSoC MCU** (consistent with the FCC). The **Ring 4** is
  probably `nomad2` or `oreo` (to confirm). `gen2`/`gen2x` bootloaders too.
- **Revised strategy**: before repackaging (anti-tamper risk), first try **pure
  static analysis** (jadx on base.apk) — it may answer (a)/(b) without breaking
  anything. jadx decompilation in progress.

### Static research leads (auth_key)
Search the decompiled code for: `auth_key`/`authKey`/`setAuthKey`,
`RingConfiguration`, `ringconfiguration`, opcode `0x24`/`36`, `nonce`,
`Authenticate`, Retrofit endpoints toward `cloud.ouraring.com`/`api.ouraring.com`
tied to device registration. Key test: where is the auth_key first assigned?

### Native libs (arm64 split) — inventory
- `libsecrets.so` (8KB): `getApiKey`/`getfallbackKey`/`getOriginalKey`/
  `customDecode` + SHA256 + obfuscated string. = hides the **app's API keys**
  (cloud/analytics). **RED HERRING** for the ring auth_key. Noted, set aside.
- `libappecore.so`, `libringeventparser.so`, `libecore.so`,
  `libwire_format_decoder_jni.so`: record parsing/decoding. **No** auth_key/nonce/
  authenticate **symbols** found (strings) → either stripped, or the
  handshake/provisioning orchestration is on the **Java/Kotlin** side. → prioritize
  the decompiled code.
- Also present: `libnexusengine.so` (16MB) + `libtorch_cpu.so` (70MB) = embedded
  PyTorch → some of the health algos run on-device.
- jadx decompiling base.apk (62k+ classes) — Java analysis pending completion.

---

## 2026-06-04 — 🎯 GO/NO-GO VERDICT: auth_key generated LOCALLY → FEASIBLE

**Static analysis of the decompiled Oura v7.16.0 code. Answer to the pivot
question: the auth_key is generated by the PHONE, not by the server. Scenario (a).
GO.**

### Proof (hardcoded in the code)
`oura/data/device/ring/g2.java:347` — method `i()`:
```java
if (!isProductionApp()) return r0.a;     // DEBUG key: {16,1,2,...,15}
UUID uuid = UUID.randomUUID();           // PROD: the key = random UUID
byte[] k = new byte[16];
ByteBuffer.wrap(k).order(LITTLE_ENDIAN)
   .putLong(uuid.getMostSignificantBits())
   .putLong(uuid.getLeastSignificantBits());
return k;                                 // 16 bytes
```
- `h.java:52`: `byte[] bArrI = g2Var.i();` then `new SetAuthKey(bArrI)` → 0x24.
- `SetAuthKey.java`: frame `[0x24][0x10][16 bytes]`, REQUEST_TAG=36, KEY_LENGTH=16.
- `w.java:44`: `dbRingConfiguration.setAuthKey(bArr)` → local persistence.
- The JSON field `auth_key` (`JsonDbRingConfiguration`) serves to **sync the key
  across the user's own devices via the cloud**, BUT the origin is local.
- **No network endpoint PROVIDES the auth_key.** The server does not generate it.

### MAJOR implication
We do NOT have to break/guess a server key. **The central is the one that CHOOSES
the key.** Our app can generate its own 16 bytes, do `SetAuthKey` (0x24), and
become the ring's authenticated device. → the "without the Oura app" goal is
FEASIBLE.

### Remaining unknown (PROTOCOL, not crypto)
In which state does the ring accept a NEW `SetAuthKey`?
- `SetAuthKey` has `RESPONSE_ERROR_PRODUCTION_TESTS_MISSING = 5` + `RESPONSE_SUCCESS=0`.
- The `Authenticate` (0x2D) handshake returns `0x02` "in factory reset",
  `0x03` "not the original onboarded device".
- Hypothesis: the ring accepts a new SetAuthKey out of the factory / after a
  reset / within an onboarding window. TO CONFIRM by observation.
- ⚠️ The ring is currently onboarded on the iPhone (already has an auth_key). To
  test a clean takeover, a reset will probably be needed (reversible).

### Consequence for the plan
- The live MITM/Frida experiment is NO LONGER the go/no-go (already answered
  statically). It remains useful to: confirm the onboarding SEQUENCE (opcode order,
  the state required for SetAuthKey), and validate that no server step is blocking.
- Priority shifts to: (1) understand the onboarding/takeover sequence via btsnoop
  capture, (2) code the BLE explorer to reproduce SetAuthKey+Authenticate.

---

## 2026-06-04 — Field observation (user) + decision to code the BLE explorer

### User's real-world experience with the physical ring
User switched iPhones a while ago WITHOUT resetting anything. On the new iPhone,
the Oura app treated the ring like a "new ring" to onboard. By simply **placing the
ring on its charger**, it appeared in the Oura app and connected immediately,
no issue. → Strong hint that **the charger opens an onboarding/pairing window**
(common anti-theft guard on wearables).

### Two competing hypotheses (cannot decide by reasoning)
- **H1 — true takeover**: the ring accepted a NEW auth_key from the new iPhone
  (charger = window to accept SetAuthKey). → ideal for us.
- **H2 — cloud re-sync**: the Oura account re-synced the EXISTING auth_key to the
  new iPhone (the JSON `auth_key` field exists precisely for cross-device sync),
  and the ring just re-authenticated with the SAME key. Charger only eased the
  reconnection, didn't authorize a new key.

Deciding H1 vs H2 requires observing the real ring. This is what the BLE explorer
+ a capture will tell us.

### Decision
Code the **macOS BLE explorer** now (read-only first: scan, connect, dump GATT,
read battery/firmware). Reasons: enough theory; the next unknowns (H1/H2, ring
state, real service presence) only resolve by observing the actual ring; zero risk
(no writes until fully mapped); runs on the Mac (CoreBluetooth); it's the
foundation of the final iOS app.

In parallel (background): static analysis of whether ResetMemory (0x1A) requires
prior auth — to know if a pure-BLE takeover (no physical reset) is possible.

---

## 2026-06-04 — 🎉 TAKEOVER SUCCESS — ring authenticated with OUR key, zero Oura

The core goal is achieved. After a factory reset (via the Oura app, which itself
requires auth first — sent `ResetMemory(false)`=`[0x1A,0x00]` at frame 2746 of the
reset capture, AFTER authenticating), the ring was keyless. Our macOS tool then:

```
connect (pairing mode) → bond (Just Works, automatic) →
SetAuthKey(0x24, OUR random 16B)  → resp 25 01 00      (0x00 SUCCESS)
GetAuthNonce(2F 01 2B)            → 2F 10 2C <15B nonce>
proof = AES-128-ECB(ourKey, nonce ‖ 0x01)
Authenticate(2F 11 2D <16B proof>) → 2F 02 2E 00        (0x00 SUCCESS) 🎉
```

→ The ring now trusts OUR key. No Oura app/cloud involved in the auth.
Proves: (a) a factory-reset ring ACCEPTS a fresh SetAuthKey with no server
validation (key is purely local, as the static analysis predicted); (b) the SMP
bond works from CoreBluetooth on macOS; (c) our AES-128-ECB proof is correct (ring
returned 0x00). Our key saved in secrets/ (git-ignored).

### Confirmed GATT (real ring, codename "oreo" / hw ORE_06)
Service 98ED0001-A541-11E4-B6A0-0002A5D5C51B:
- 98ED0002 [write/writeNoResp]      ← command WRITE (handle 0x0015)
- 98ED0003 [read,notify]            ← response NOTIFY (handle 0x0012)
- 98ED0004 [read,write,notify,indicate]
- 98ED0005 [writeNoResp,notify]
- 98ED0006 [writeNoResp,notify]
Service 00060000-F8CE-11E4-ABF4-0002A5D5C51B: 00060001 [write,notify] (DFU?)

### Bug found & fixed
First takeover attempt wrote to the wrong characteristic: a property-based
heuristic matched 98ED0004 (also write+notify) instead of 98ED0002/98ED0003.
Fixed by matching exact UUIDs. Lesson: target Oura chars by UUID, not properties.

### Next
- Read real data: enable notifications + GetEvent (0x10) / battery (0x0C) /
  product info (0x18) / live stream. Decode TLV records (PPG/IBI/accel/temp).
- Port this to the iOS app (ios-app/), reusing OuraProtocol.swift.

---

## 2026-06-04 — ✅ Key persistence CONFIRMED (--auth mode)

Reconnected WITHOUT re-sending SetAuthKey — only the handshake (GetAuthNonce →
Authenticate with our saved key) → ring returned 0x00. The ring durably stored
our key. Fresh nonce each time (09 12 63 b0… vs a5 2d 80 8d… at takeover) proves
a real challenge-response. We can re-authenticate at will, no pairing mode, no Oura.

### Safety net for key loss (researched, NOT tested to avoid losing our takeover)
- Physical factory reset exists: ring on powered charger, tap charger on a hard
  surface ~5-10×; some models have a side button. (Community sources — to confirm
  on Ring 4.) → losing the key is recoverable via physical reset, ring not bricked.
- App factory reset = ResetMemory after auth (anti-theft: needs the current key).

### Modes now in the explorer
--oura (scan+connect), --connect <uuid>, --name <s>, --takeover (set our key),
--auth <hexkey> (authenticate with saved key), --selftest (AES KAT), default scan.

---

## 2026-06-04 — Key secured (Keychain) + in-app reset coded

- **Keychain**: `--store-key <hex>` migrates the auth_key into the macOS Keychain
  (encrypted at rest). `--takeover` now auto-stores on success. `--auth`/`--reset`
  load from Keychain when no key is passed. Verified: `--auth` (no arg) loaded the
  key from Keychain and authenticated (fresh nonce, 0x00). Plaintext
  secrets/ring-auth-key.txt kept as a manual backup (git-ignored) — user to also
  back up the key in a personal password manager.
- **--reset** mode coded (NOT run, to keep our takeover): authenticates with our
  key, then sends ResetMemory `[0x1A 0x00]` (mirrors the captured app reset). Lets
  us hand the ring back to Oura cleanly. Note: needs the current key (anti-theft);
  the physical charger-tap reset is the fallback if the key is lost.

### Explorer command surface (final for this phase)
--oura · --connect <uuid> · --name <s> · --takeover · --auth [hex] · --reset [hex]
· --store-key <hex> · --selftest · (default) scan-all

---

## 2026-06-04 — "Restricted mode" experiment: takeover holds against Oura ✅

User tried to reconnect the (taken-over) ring to the official Oura app on Android
WITHOUT factory-resetting first. Result:
1. Pairing mode → Oura app connects at BLE level.
2. App authenticates with ITS old Oura key → ring has OUR key → mismatch →
   ring rejects (matches code 0x03 "not original onboarded device").
3. App entered **"RESTRICTED MODE — only factory reset possible"**.
4. User had to factory-reset to let the Oura app reclaim the ring.

This is strong confirmation of our whole model:
- Our takeover was real and robust: the official app + the user's own account
  COULD NOT reclaim the ring while our key was set.
- "Restricted mode" == the 0x03 FAILURE_NOT_ORIGINAL_ONBOARDED_DEVICE state. The
  ring only allows a factory reset to a non-owning authenticator. Anti-theft works.
- The loop is fully reversible both ways: Oura→us (takeover after reset) and
  us→Oura (app reclaims after reset).

⚠️ Consequence: the factory reset ERASED our key from the ring; Oura re-onboarded
it with a fresh Oura key. Our stored key <stale-key… is now STALE (no longer matches
the ring). Cleared it from the Keychain. We'll re-takeover (new random key) after
the next factory reset.

---

## 2026-06-04 — Re-takeover successful (new key) + Mac bond gotcha

After the user re-onboarded to Oura then factory-reset again, we re-took the ring.

- **Gotcha**: first re-takeover attempt failed with "Peer removed pairing
  information" — the Mac cached a stale BLE bond (LTK) from the FIRST takeover,
  but the ring had since been reset (dropped its side). Fix: forget the ring in
  macOS System Settings → Bluetooth (real MAC <mac-redacted>). Then takeover
  succeeded cleanly (fresh bond). → The iOS app must handle/clear stale bonds on
  re-takeover.
- New key set & stored in Keychain (auto). Ring authenticated (0x00). Full cycle
  proven twice, both directions.

### Note for iOS app
Stale-bond handling is required: on "peer removed pairing information", clear the
system bond (or guide the user to forget the device) before reconnecting.

---

## 2026-06-05 — DATA RETRIEVAL working (`--read`): infos + TLV history decoded

Added a `--read` mode to `ble-explorer`. After the saved-key handshake it replays
the app's post-auth init, queries device info, then opens the data plane. **First
real data read from the ring without the Oura app — both simple infos and decoded
TLV records.**

### What now works (verified on the real ring, worn)

**Simple infos (request → response tag = request opcode + 1):**
- `GetFirmwareVersion (0x08 03 00 00 00)` → `09 …`: firmware bytes
  `02 00 00 02 0b …` → version **2.0.0.2.11** family.
- `GetBatteryLevel (0x0C 00)` → `0d 06 60 …`: `0x60 = 96%`.
- `GetProductInfo (0x18 03 <sub> 00 10)` → `19 11 00 …` ASCII identity:
  `9131`, **`ORE_06`** (codename oreo), serial **`2016092441019131`**
  (= the ring's BLE name).

**Post-auth init acks observed:** `17`=SetBleMode, `13`=SyncTime (body carries the
ring's current ringTimestamp, e.g. `0x00057640`), `1d`=SetNotification,
`29`=data_flush.

**The stream trigger:** `SetNotification (1c 01 bf)` alone stays SILENT. It is
**`data_flush (0x28 01 00)`** that releases the buffered events onto the BLE notify
stream. We now send it unconditionally to open the firehose. (Confirmed against
open_ring's PROTOCOL.md and then on our ring: data_flush → ~250 records.)

**GetEvent (history) wire format corrected to 11 bytes:**
`10 09 <cursor u32 LE> <max_events u8> <flags u32 LE=FFFFFFFF>`.
`--read --history` dumps from cursor 0 (full flash history).

### TLV record decode — VALIDATED on our own data

Format `[type:1][len:1][ctr_lo ctr_hi][ses_lo ses_hi][payload(len-4)]`,
`ringTimestamp=(session<<16)|counter`. Our decoder framed ~256 back-to-back records
cleanly (counters increment 1393,1394,1395…). Types seen in this dump:

| Type | Name | Content (decoded from real payloads) |
|------|------|--------------------------------------|
| `0x41` | boot/start | `10 00 00 00 32 02 0b …` → fw `2.0.b…` at boot |
| `0x42` | time-anchor | unix ts LE — e.g. `08 ef 21 6a` → wall-clock anchor for ringTimestamps |
| `0x43` | **diag-log** | **ASCII** text lines (NEW finding). Examples below. |
| `0x61` | event | binary event/counter records |

`0x43` diagnostic strings decoded from the boot log:
`git;29df664` (fw commit), `SNH;019131`+`SNL;2016092441` (serial halves),
`HWID;ORE_06`, `acm_bma456` (**accelerometer = Bosch BMA456**), `MFC;500;4`,
`rdata init`, `in_bed=0`, plus charge telemetry `chgv;…`, `chg_hs;…`, `chg_rp;…`,
`FGdcap;39`, `BMVbI;50`.

### Not yet captured: raw biosignals (PPG 0x81 / IBI 0x80 / accel 0x33 / temp)

The history we pulled was dominated by **system/charge events** (the ring had just
been on the charger). No 0x80/0x81/0x33 records appeared yet. Hypothesis: the ring
pauses PPG measurement during an active BLE connection, and/or a measurement-start
opcode is needed. **Next session**: chase the biosignals (see NEXT.md).

### Files
- `OuraProtocol.swift`: added `getFirmwareVersion`, `setBleMode`, `syncTime`,
  `setNotification`, `dataFlush`, fixed `getEvent` (11B), `Record` + `decodeRecords`
  (defensive TLV walk), `recordTypeName`.
- `main.swift`: new `.read(key, seconds, history)` mode; `--read [hex] [--history]
  [--seconds N]`; post-auth staged sequence; `handleReadNotification` (info vs TLV);
  rolling `streamLeftover` buffer for cross-notification record framing; per-type
  summary at the end.

---

## 2026-06-05b — Biosignals: measurement TRIGGER found + live AFE stream (worn ring)

Chased the raw biosignals. Key unlock: the ring does NOT emit physiological records
just because you connect + `data_flush`. It needs an explicit **feature subscribe**.

### How we found it
The first `--read --history` dump (ring fresh off charger) returned ~256 records but
all system/charge events (`0x43` ASCII logs, `0x61`), no PPG/IBI. A second run with an
empty flash buffer returned **zero** records → `data_flush` only drains existing
buffer; it doesn't start measurement.

Decoded the onboarding btsnoop (`captures/poura-onboarding.btsnoop`, frames 926-992)
with tshark to get the app's exact post-battery sequence. It runs a feature
get/set/**subscribe** block via ext `0x2F`:
```
get:        2f 02 20 <id>          → 2f 06 21 <id> <4B value>
set:        2f 03 22 <id> <val>    → 2f 03 23 <id> <val>     (ack)
subscribe:  2f 03 26 <id> <val>    → 2f 03 27 <id> <code>    (ack)  ← the trigger
```
The decisive pair before the stream opens: `2f 03 22 02 03` (set feat 0x02=3) then
`2f 03 26 02 02` (**subscribe feat 0x02=2**), then `28 01 00` (data_flush).

### Result on OUR worn ring (verified)
Implemented the subscribe block in `--read`. On a worn ring it produces a **live
data stream** — continuous notifications, no Oura app:
```
2f 0f 28 02 <chan> 02 00 00 <value u16 LE> 00 00 00 00 59 0a 7f
```
- `chan` ∈ {0x09, 0x19}. Channel 0x09 value ≈ **5150 ± 60**, stable at rest, jumps
  (13191, 8726…) when the finger moves. → very likely the **PPG DC level** (mean
  reflected light), a real physiological signal.
- Rate ≈ 0.5–1 Hz. This is an AFE stat/quality channel, **not** the high-rate AC
  PPG waveform.

### Probed all features, only 0x02 streams
Added `--features <hex,…>` to subscribe to arbitrary feature IDs. Subscribed to
`0x02,0x03,0x04,0x0b,0x0d,0x10` (all the ones the app gets). **All ACK the subscribe
(`2f 03 27 <id> 02`) but only 0x02 emits data.** The high-rate PPG waveform + IBI
(beat intervals) did not appear.

### Open question (honest status)
The raw high-frequency PPG (`0x81`, AC waveform) and IBI (`0x80`/`0x60`, beat
intervals) are **not** streamed by feature 0x02 on a connected, idle worn ring.
Most likely the ring only runs high-rate PPG during **scheduled measurement sessions**
(sleep / spot-check), not continuously over an active BLE link (power). The
onboarding capture's `0x81`/`0x80` records were emitted during a measurement
transition, not steady-state streaming. Next: trigger/observe a measurement session,
or find the feature/flag that forces continuous high-rate PPG.

### Decoders added (verified formats, ready for when those records appear)
From the onboarding capture + open_ring cross-ref (an `Explore`-style sub-agent
decoded the capture; we kept only byte-verified claims):
- `0x46` TEMP: 3× i16 LE /100 = °C.
- `0x80` GREEN_IBI_QUALITY: N× u16 LE; bits 0-10 = IBI ms, 11-13 qual_a, 14-15 qual_b
  (clean beat = qual_a≤1 & qual_b==0).
- `0x60` IBI+amplitude: bit-packed (left raw — packing needs worn-data validation).
- Record type names extended: 0x46 temp, 0x47 motion, 0x53 wear, 0x60 IBI+amp,
  0x61 debug-data (payload[0]=sub-dispatch), 0x79 AFE-tuning.
- ⚠️ Correction from the capture decode: `0x3d` is NOT a top-level type — it's a
  `0x61` sub-type (charger debug), so those dense bytes were charge telemetry, not PPG.

### Files
- `OuraProtocol.swift`: `featureGet/Set/Subscribe`, `decodeBiosignal` (0x46/0x80),
  extended `recordTypeName`.
- `main.swift`: subscribe block in the read sequence (loops `--features`); live
  `0x2F/0x28` stream decoder (chan + value); `--features <hex,…>` flag;
  `streamSampleCount` in the summary.
- Local captures (git-ignored): `poura-live-worn-stream.log`, `poura-feature-probe.log`.

---

## 2026-06-05c — 🎉 BIOSIGNALS RETRIEVED (IBI, temp, motion) via recent-cursor GetEvent

Got real physiological data off the worn ring, no Oura app. The unlock was the
**GetEvent cursor**, not a stream subscribe.

### The real mechanism (corrects 2026-06-05b)
Re-decoded the onboarding capture: the app's biosignal records (108× 0x81 PPG,
47× 0x80 IBI, 41× 0x60, 90× 0x46 temp) arrived as the **response to a GetEvent
(0x10) with a RECENT cursor** (`10 09 98e50f15 00 ffffffff`, cursor 0x150fe598) —
NOT from the feature-subscribe live stream. Our `--history` used `cursor=0`, which
only replays the oldest flash pages (boot/charge log), so we never reached the
recent measurement records.

Confirmed the app's own capture DID contain biosignals (sub-agent TLV walk over the
whole btsnoop): 0x81×108, 0x80×47, 0x60×41, 0x46×90. So the data was always there;
we were fetching from the wrong cursor.

### Fix + result
Added `--cursor recent|<hex>`: `recent` reads the ring's current ringTimestamp from
the SyncTime ack, subtracts a small window (~0x2000 ticks), and fetches from there.

`--read --cursor recent` on the worn ring returned (one 12 s run):
- **0x80 IBI-quality × 42**, **0x60 IBI+amp × 47** (heart-rate data)
- **0x46 temperature × 11** — decoded cleanly: `[25.8, 28.0, 21.4]°C` (skin / internal
  / ambient), stable and physiologically plausible. ✅
- **0x47 motion × 11**, plus 0x42 anchor, 0x45 state, 0x5b/0x5d/0x6c/0x72/0x82/0x83.

Our ring's ringTimestamps are session=5 (a lightly-used ring), e.g. ts≈387060;
cursor `recent` resolves to ~0x5e000 and lands right on the live measurement records.

### Honest status on decoding
- **Temp (0x46)** decode VERIFIED (3× i16 LE /100 °C).
- **IBI (0x80)** records are framed correctly but the **bit-packing of IBI-ms vs
  quality is NOT yet validated** — the bits-0..10 split gives incoherent intervals
  (jumps 100↔1900 ms). Changed the decoder to print raw u16 words (`packing TBD`)
  rather than assert wrong "ms". Same for 0x60 (dense 14-byte payload, undecoded).
- **0x81 raw PPG** did not appear in this short window (it's the highest-volume type
  in the app capture; expect it in a longer/again run). Decoder still TODO
  (delta-encoded, stateful).

### Files
- `OuraProtocol.swift`: 0x80 decoder now prints raw u16 words (honest, packing TBD).
- `main.swift`: `--cursor recent|<hex>`; capture ring-now ringTimestamp from SyncTime
  ack; `resolveHistoryCursor()`.
- Local capture (git-ignored): `captures/poura-biosignals-recent.log`.

### Next
Decode 0x80/0x60 IBI packing (validate against a known HR, or open_ring decoders.py
L231/L417), and capture 0x81 raw PPG in a longer recent-cursor pull. Then HR/HRV.
