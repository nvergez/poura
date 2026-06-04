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
