# Capture analysis — real Android onboarding (2026-06-04)

> Source: `captures/poura-onboarding.btsnoop` — full HCI snoop of a SUCCESSFUL ring
> onboarding on the Solana (Android), Oura app v7.16.0. Ring was previously
> onboarded on the iPhone; here it re-onboarded on Android.
> 1355 frames: 371 ATT, 15 SMP. ⚠️ This capture contains the auth proof and
> link-layer key material → treat as SENSITIVE (git-ignored).

## The full connection picture (now confirmed empirically)

```
1. PAIRING MODE: physically remove ring from charger + put it back
   → charger light blinks WHITE → BLE connection window opens.
   (Without this, the ring advertises connectable=YES but DROPS the GATT
    connection after ~3s. This was the mystery blocker.)
2. GATT connection
3. SMP pairing / LE Secure Connections → bond (LTK), "Just Works"
4. App-layer auth: GetAuthNonce (0x2B) → Authenticate (0x2D) with a 16-byte proof
```

## 🚨 KEY FINDING: NO SetAuthKey (0x24) in this onboarding → it's H2, not H1

The captured sequence does **GetAuthNonce → Authenticate directly**, with **no
`SetAuthKey` (0x24)**. Meaning:
- The ring already had an auth_key (from the original iPhone onboarding).
- The Oura **account re-synced that SAME auth_key** to the Android app via the
  cloud (the JSON `auth_key` field is exactly for cross-device sync).
- Android just **authenticated with the existing key** — no new key was set.

→ This answers our H1 vs H2 question: **H2 (cloud re-sync of the existing key)**.
The "pairing mode" (charger cycle) only opens the BLE connection window; it does
NOT by itself wipe/replace the auth_key.

**Implication for the zero-Oura goal**: to authenticate, we need THE ring's current
auth_key. Two paths remain:
- (i) Extract the existing auth_key from a device that has it (the Android Realm
  `assa-store.realm` now has it, or the iPhone). Then our app can authenticate.
- (ii) Force the ring into a true factory-reset state (no key) so it accepts OUR
  `SetAuthKey` — needs to confirm how to trigger that (physical reset vs BLE).

## App-layer auth sequence (ATT writes to handle 0x0015)

| Frame | Bytes | Meaning |
|-------|-------|---------|
| 857 | `08 03 000000` | GetFirmwareVersion (0x08) family |
| 861 | `2f 02 0100` | ext 0x2F → sub 0x01 (GetCapabilities) |
| 865 | `2f 02 0101` | ext sub 0x01 |
| 869 | `2f 01 2b` | **GetAuthNonce (0x2B)** — request nonce |
| 873 | `2f 11 2d <16-byte proof> 01` | **Authenticate (0x2D)** — proof = AES(auth_key, nonce…) |
| 877 | `16 01 02` | SetBleMode (0x16) |
| 889 | `12 09 d5e4216a 00000000 04` | SyncTime (0x12) — unix ts LE |
| 893 | `1c 01 bf` | SetNotification (0x1C) |
| 897–917 | `18 03 14/18/28/34/04/08 00xx` | GetProductInfo (0x18) sub-queries |
| 921 | `0c 00` | GetBatteryLevel (0x0C) |
| 926–966 | `2f …` | feature get/set (ext 0x2F: 0x20/0x22/0x26 …) |
| 993 | `28 01 00` | data_flush / CheckSleepAnalysis (0x28) |
| 997,1019 | `10 09 …` | GetEvent (0x10) — history fetch by cursor |
| 1154+ | `20 …` | SetUserInfo (0x20) |

Note: the `0x2F` base-tag + sub-tag "extended" scheme our static agent inferred is
**CONFIRMED here** (e.g. `2f 01 2b` = GetAuthNonce, `2f 11 2d …` = Authenticate).

## SMP / link-layer security (frames 649–689)

Confirmed there IS real BLE pairing (this nuances the app code's "no bonding
required" — the ring DOES bond):

```
Pairing Request : SecureConnections=1, MITM=1, Bonding ; IO=Keyboard/Display ; KeySize=16
Pairing Response: SecureConnections=1, MITM=1, Bonding ; IO=NoInput/NoOutput  ; KeySize=16
Key distribution: LTK + IRK + CSRK
```
- IO = NoInput/NoOutput on the ring → association falls back to **Just Works**
  (no PIN — matches the user's experience). MITM requested but unsatisfiable.
- **IRK distributed** → explains the Resolvable Private Address (the ring's BLE
  identifier rotated between scans). A bonded central resolves it via the IRK.

## GATT handles seen
- Write (commands): handle `0x0015` (write).
- `0x0013` written `2f02...`? (CCCD / notify enable around frame 845).
- Notify characteristic: under service `98ed0001…` (per research, char `98ed0003`).
- Frame 752 writes handle `0x0004` (ATT MTU/CCCD region).

## Open questions raised by this capture
1. To go zero-Oura we still need the auth_key. Extract from Android Realm now?
2. Can we replay the SMP bond from macOS/iOS (CoreBluetooth abstracts the LTK)?
3. Exact CCCD enable + MTU exchange order to keep the link alive in pairing mode.

---

## Auth handshake DECODED byte-by-byte (frames 869-876)

```
869 →ring:  2f 01 2b                          GetAuthNonce
872 ring→:  2f 10 2c | <15-byte nonce>        GetAuthNonce response
            nonce = 0e 35 0b 8c 26 f0 11 84 e8 98 53 6c 65 26 66   (15 bytes)
873 →ring:  2f 11 2d | <16-byte proof>        Authenticate
            proof = 90 42 c4 89 71 fe 86 11 14 a5 1e 2b c1 a5 8c 01 (16 bytes)
876 ring→:  2f 02 2e 00                       AuthResponse = 0x00 SUCCESS ✅
```
Confirms: nonce = 15 bytes → `nonce ‖ 0x01` = 16 = one AES block.
proof = 16 bytes. Per research: `proof = AES_128_ECB(auth_key, nonce ‖ 0x01)`.
(Cannot re-verify the AES mode without the key; two sources concur — validate
empirically after we set OUR key.)

## Ring identity (from GetProductInfo responses, frames 900-920)
- 900: `19 11 00 <serial-redacted> 4f52455f3036 …` = ASCII serial + "ORE_06"
- 904: `19 11 00 4f52455f3036 …` = "ORE_06"
- 916/920: "<build-id-redacted>" / "<serial-redacted>" — firmware/build ids
→ Hardware type "ORE_06" maps to codename **oreo** → **this ring is "oreo"**
  in Oura's nomenclature (one of the Ring 4 variants).

## Extended-tag (0x2F) opcode map (CONFIRMED from capture)
| sub | dir | meaning |
|-----|-----|---------|
| 0x01 | req/resp | GetCapabilities |
| 0x2B | req | GetAuthNonce |
| 0x2C | resp | GetAuthNonce response (15-byte nonce) |
| 0x2D | req | Authenticate (16-byte proof) |
| 0x2E | resp | AuthResponse (00=success) |
| 0x20/0x22/0x26 | req | feature get/set/subscription |
| 0x21/0x23 | resp | feature responses |

## Direct opcodes (handle 0x0015 write / 0x0012 notify) CONFIRMED
0x08 GetFirmwareVersion · 0x0C GetBatteryLevel · 0x10 GetEvent ·
0x12 SyncTime · 0x16 SetBleMode · 0x18 GetProductInfo · 0x1C SetNotification ·
0x20 SetUserInfo · 0x28 data_flush. (0x24 SetAuthKey NOT used here — H2.)

## GATT handles (confirmed)
- Write characteristic: handle **0x0015** (commands)
- Notify characteristic: handle **0x0012** (responses) — CCCD at 0x0013
