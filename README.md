# poura

Reverse engineering the **Oura Ring 4** to connect to it over BLE and read its
data **without going through the Oura app or Oura's servers**.

> Ring purchased and owned 100% by the author. RE for interoperability and
> personal-use purposes (legal in France/EU — art. L122-6-1 CPI). No
> redistribution of Oura firmware, no circumvention of Oura's servers for
> commercial purposes.

## Status

🟡 Phase 0 — Recon & documentation. No application code yet.

## Goals

### Current goal (the challenge)
**Pair with the ring and read its data without the official Oura app, from scratch.**
See [`docs/STRATEGY.md`](docs/STRATEGY.md) — it's harder than it looks, and the
go/no-go hinges on a precise crypto question (the origin of the `auth_key`).

### Longer-term goal (documented for later)
A native, standalone iOS app (Swift / CoreBluetooth) that talks directly to the
ring. **Clean-room implementation in Swift**, using the existing projects
(`open_ring`, `ringverse`) only as **reference documentation**, not as a code
base.

## What the research established (summary)

- The Oura Ring 4 BLE protocol **has already been publicly RE'd** (`open_ring`,
  `ringverse`). GATT, opcodes, formats, AES-128-ECB handshake: documented.
- **Known WALL**: the ring requires a unique 16-byte `auth_key`, generated during
  official onboarding (Oura account + servers) and never publicly derived. Without
  it, the ring responds `0x03` "not the original onboarded device".
- You only get the **raw biosignals** (PPG, IBI, accelerometer, temp, battery) —
  not the sleep/readiness scores (computed in the Oura cloud).
- The **Gen3** BLE protocol is NOT publicly documented. Everything here targets the Ring 4.

Full details and sources in [`docs/PROTOCOL.md`](docs/PROTOCOL.md).

## Hardware setup

- **Mac**: dev (Xcode; CoreBluetooth is also available on macOS for exploration).
- **Physical iPhone**: real BLE (the iOS simulator has no Bluetooth).
- **Android**: BLE sniffing via HCI snoop log (btsnoop) — much simpler than iOS.

## Directory layout

```
docs/          Documentation: strategy, protocol, investigation journal
research/      RE notes (APK analysis, decoded captures)
captures/      btsnoop captures / raw BLE logs (git-ignored if large/sensitive)
ble-explorer/  BLE exploration tool (macOS/CLI) — scan, connect, dump GATT
ios-app/       The final iOS app (Swift)
```

## ⚠️ Feasibility warning

Pulling off "pair without the Oura app" means succeeding at **A** (BLE bond —
feasible) **AND** **B** (`auth_key` handshake — novel research, possibly
infeasible). We only commit to B after the key-origin investigation. See
STRATEGY.md.
