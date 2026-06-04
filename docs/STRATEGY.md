# Strategy

## The guiding principle of RE: observe before coding

We don't code the app first. In reverse engineering, you **observe** the real
system, **understand** the protocol, *then* implement. Coding blind = rewriting it
three times.

## Untangling "pair without the Oura app": two distinct problems

This is THE clarity point of the project. "Pair without the app" conflates two
radically different layers of difficulty:

### Problem A — The BLE bond (standard Bluetooth layer) — FEASIBLE
Classic Bluetooth pairing: negotiation, LTK, bond. CoreBluetooth (iOS/macOS)
handles it natively. A reset ring (factory mode) will most likely accept a BLE
pairing from any central. **This is our first concrete milestone.**

### Problem B — The `auth_key` application handshake (Oura crypto layer) — THE WALL
After the bond, the ring requires an application-level handshake:

```
Set Auth Key (0x24)   → 16-byte key UNIQUE to the ring
Get Auth Nonce (0x2B) → the ring returns a 15-byte nonce (response 0x2C)
proof = AES_128_ECB(auth_key, nonce ‖ 0x01)[:16]
Authenticate (0x2D)   → we submit the proof
  0x00 = success
  0x03 = "not the original onboarded device"  ← the wall
```

This `auth_key` is generated during official onboarding (on Oura's servers) then
hidden in the app. **Nobody, publicly, knows how to derive or compute it.**

## The project's go/no-go question

> **Where does the `auth_key` come from?**
>
> - **(a)** Derived from a hardware secret present in the ring (e.g. a seed derived
>   from a device identifier, a firmware master key…) → **there is hope**, we can
>   try to recover the derivation function by RE.
> - **(b)** Pure randomness generated server-side by Oura, merely "deposited" into
>   the ring at onboarding → **mathematically hopeless** without the server. There
>   is nothing to "find": the key is derivable from nothing.

We **cannot** answer this by reasoning. We have to **investigate**:
1. RE the native libs of the Oura Android APK (`libappecore.so`,
   `libringeventparser.so`) — look for the auth_key generation/derivation.
2. Sniff the onboarding (btsnoop) — see whether the key transits over the network
   (→ b) or is computed locally on the phone/ring (→ a possible).

**This investigation is the project's pivot.** If (b) → we pivot to the long-term
goal (onboard once, extract the key, then standalone app). If (a) → we attempt the
real zero-Oura challenge.

## Phases

| # | Phase        | Goal | Status |
|---|--------------|------|--------|
| 0 | Recon        | Docs + mapping the existing work (open_ring, ringverse) | 🟡 in progress |
| 1 | Sniff        | Capture official onboarding BEFORE any reset (ref.) | ⬜ |
| 2 | Explore      | macOS tool: scan, connect, dump the ring's GATT | ⬜ |
| I | **Auth-key** | **Investigate auth_key origin → go/no-go (a vs b)** | ⬜ |
| 3 | Pairing A    | Establish the BLE bond from our central | ⬜ |
| 4 | Decoding     | Per result I: attempt the handshake / decode records | ⬜ |
| 5 | iOS app      | Build the Swift app on top of what works | ⬜ |

## ⚠️ Critical ordering on the RESET

**Do NOT reset the ring before sniffing the onboarding.** The ideal sequence:

1. Sniff the ring **in its current state** (normal sync traffic).
2. *Then* sniff a **full reset + re-onboarding** — this is THE moment when the key
   exchange / auth_key provisioning happens. The most valuable capture of the whole
   project.

Resetting before sniffing = permanently losing the trace of the key provisioning,
which is exactly what we're trying to understand.

## Named risks

- **B may be infeasible** (case (b)). Non-negligible probability — locking this
  down is Oura's business model.
- The Swift port of the BLE crypto/timing may reveal discrepancies vs Linux/BlueZ
  (MTU, write-without-response, notification ordering).
- `open_ring` is a single, lightly-starred repo: **every fact in it is to be
  re-validated** against our own captures before relying on it.
- iOS abstracts BLE pairing (no raw LTK access) — may complicate importing an
  existing bond if it comes to that.
