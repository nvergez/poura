# Android setup — Decisive experiment: origin of the auth_key

> **Goal**: during the ring's onboarding on the **Android** Oura app (the ring is
> already onboarded on the iPhone but NOT on the Android → we can onboard on the
> Android side without resetting anything), observe where the 16 bytes of the
> `auth_key` come from: an Oura server response (→ infeasible without the server)
> or a local computation (→ hope).
>
> **Device**: Solana Mobile (Saga/Seeker), **non-rooted**. Approach: no-root first
> (APK repackaging + frida-gadget + MITM). Escalate to root only if Oura's
> anti-tamper blocks us.

## Plan overview

```
1. Install the Mac toolchain (adb, frida, objection, mitmproxy, apktool)
2. Connect the Solana over USB + enable USB debugging
3. Retrieve the official Oura APK (from the phone or APKMirror)
4. Repackage the APK with objection (injects frida-gadget + disables cert-pinning)
5. Install the patched APK + launch mitmproxy (custom CA)
6. (Unpair the ring from the iPhone if needed — reversible)
7. Onboard the ring on the patched Oura app WHILE CAPTURING (MITM + Frida hooks)
8. Analyze: where do the 16 bytes of the auth_key come from?
```

⚠️ **Risks** (already named):
- The repackaged/re-signed APK may be rejected by Oura's anti-tamper.
- The app may detect Frida/instrumentation and refuse onboarding.
- If it blocks → we evaluate rooting (bootloader unlock + Magisk, wipes the phone).

---

## Step 1 — Mac toolchain

```bash
# Android + RE tools (Homebrew)
brew install --cask android-platform-tools   # adb, fastboot
brew install apktool                          # decompile/recompile APK
brew install mitmproxy                        # HTTPS interception proxy

# Frida + objection (Python). Isolated in a venv so we don't pollute pyenv.
python3 -m venv ~/.poura-venv
source ~/.poura-venv/bin/activate
pip install frida-tools objection

# Checks
adb version
frida --version
objection version
mitmproxy --version
apktool --version
```

> Signing note: `objection patchapk` downloads `uber-apk-signer` as needed (Java 24
> already present). If a signature issue arises, manual fallback with `apksigner`
> (included in the SDK build-tools).

---

## Step 2 — Connect the Solana Mobile

On the phone: **Settings → About → tap the build number 7×** to unlock developer
options, then **Developer options → USB debugging = ON**.

```bash
adb devices          # should list your Solana (accept the RSA popup on the phone)
adb shell getprop ro.product.model   # confirm the model
adb shell getprop ro.build.version.release  # Android version
```

---

## Step 3 — Retrieve the Oura APK

Option A (recommended — the exact build that will run) if Oura is already installed:
```bash
adb shell pm path com.ouraring.oura   # lists the paths (often a split APK)
# pull each line base.apk + split_*.apk:
adb pull /data/app/.../base.apk ./captures/oura-apk/
```
If multiple splits → merge them into a universal APK before patching:
```bash
# via APKEditor (jar): java -jar APKEditor.jar m -i ./captures/oura-apk/ -o oura-merged.apk
```

Option B: download from **APKMirror** (search "Oura", build 2024+ for the Ring 4).
Prefer the bundle then merge.

---

## Step 4 — Repackage with objection (no root)

```bash
source ~/.poura-venv/bin/activate
objection patchapk -s oura-merged.apk
# → produces oura-merged.objection.apk (frida-gadget injected + permissive network_security_config)

adb install oura-merged.objection.apk
```

If the install fails (conflicting signatures): `adb uninstall com.ouraring.oura`
first (⚠️ this removes the unpatched Oura app from the Android — OK since it isn't
onboarded there).

---

## Step 5 — MITM (HTTPS capture)

```bash
# 1) Launch mitmproxy in proxy mode
mitmweb --listen-port 8080    # web UI at http://127.0.0.1:8080

# 2) Route the phone through the Mac: phone Wi-Fi → manual proxy = MAC_IP:8080
#    (Mac and phone on the same network)

# 3) Install the mitmproxy CA on the phone: browse to http://mitm.it from the
#    phone, install the Android profile. (User CA; the network_security_config
#    injected by objection makes it trusted for the patched app.)
```

Filter the Oura traffic in mitmweb: domains `*.ouraring.com`,
`cloud.ouraring.com`, `api.ouraring.com`.

---

## Step 6 — Frida hooks (as backup)

Once the patched app is running, it exposes frida-gadget:
```bash
frida-ps -Uai                       # lists apps; spot com.ouraring.oura
objection -g com.ouraring.oura explore
# in objection:  android hooking search classes ring   (look for RingConfiguration)
#                android hooking watch class <class>    (trace set auth_key)
```
Targeted Frida script (to refine after jadx): hook the auth_key write into the
Realm and log the value + the call stack.

---

## Step 7 — Captured onboarding

1. If the ring refuses to pair with the Android (already bonded to the iPhone):
   unpair on the iPhone side (Oura app → ring settings → forget/unpair).
   **Reversible**: you'll re-onboard the iPhone afterward.
2. mitmweb + Frida armed.
3. Start the onboarding in the patched Oura app. Go until the ring is
   recognized/activated (the moment the auth_key is provisioned).

---

## Step 8 — Analysis (the verdict)

The 16 bytes of the auth_key (retrievable afterward from `assa-store.realm` after
the marker `41 41 41 41 11 00 00 10`):

- **Appear in an HTTP response** from a device registration endpoint
  → **(b) server-side → zero-Oura infeasible.** Pivot to the long-term goal.
- **Appear nowhere on the network** but are written by a local function fed by the
  ring's serial/MAC → **(a) → hope, we RE the derivation.**
- Intermediate case (key wrapped/encrypted in transit) → analyze more closely.

Record the verdict in `docs/JOURNAL.md`.
