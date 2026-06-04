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
