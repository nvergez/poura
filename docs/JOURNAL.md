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
