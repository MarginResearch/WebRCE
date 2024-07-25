WebRCE
===

This repository contains code supporting the Signal-iOS research presented in
Margin Research's
['You Can't Spell WebRTC without RCE'](https://margin.re/2024/07/you-cant-spell-webrtc-without-rce-part-1/)
blog series.

# Part 1

Instructions for following along with
[Part 1](https://margin.re/2024/07/you-cant-spell-webrtc-without-rce-part-1/)
of the blog series.

## Building

Building requires downloading Google's `depot_tools` and setting an environment
variable:

```bash
git clone https://chromium.googlesource.com/chromium/tools/depot_tools
export DEPOT_TOOLS=`pwd`/depot_tools"
```

You'll also need [rustup](https://rustup.rs) for building on all platforms and
`coreutils` which can be downloaded on macOS from brew:

```
brew install coreutils
```

This POC uses the following versions:
* Target: Signal-iOS v7.13.0.131, RingRTC v2.42.0, WebRTC tag 6261i (with
injected WebRTC vulns)
* Thrower: Signal-Android v7.10.3 (with debug symbols) emulated using Google
Pixel 6, Android 11, API 30 from Android Studio devices
* Frida-server v16.3.3

### iOS

Build the app with debug symbols for deployment in Xcode's Simulator to follow
along with injecting and triggering the vulnerabilities in Part 1 of the blog.
Set the `DEPOT_TOOLS` environment variable as outlined above and run `make
build-ios-debug`. This will fetch Signal-iOS, download dependencies, patch
WebRTC, and recompile Signal-iOS with the injected vulnerabilities. Load the
resulting `Signal-iOS-debug` project in Xcode and boot the app in a Simulator
of your choice.

### Android

The "Thrower" can be any device with Signal installed including WebRTC
debug symbols, and it is easiest to do this by compiling `Signal-Android` from
source. **Compilation must occur on a Linux device**.

Set the `DEPOT_TOOLS` environment variable as noted above and run `make
build-android-debug`. This will fetch Signal v7.10.3 and build from source using
Docker reproducible builds. It will also handle creating a signing keychain and
signing the APK. Once complete, the signed APK in
`$(PWD)/Signal-Android-play-prod-arm64-v8a-debug-7.10.3_signed_aligned.apk`
can be installed in an emulated Android device by dragging and dropping. Android
Studio devices, such as the Pixel 6 device noted in this README's intro, work
just fine for this purpose.

## Running

Ensure the target device is running in Xcode's Simulator.
Ensure both devices have Signal installed (the iOS Simulator should have the
debug build including injected vulnerabilities) with registered unique
phone numbers.

Send a message from one device to the other and accept the receipt so both
users are in one another's contact book. _The Target device must accept messages
from the attacker for this POC to work_.

### Frida

Install Frida using pip with `pip install frida-tools`.

Download a precompiled [frida-server](https://github.com/frida/frida/releases)
and load onto the throwing device with
`adb push <path to frida-server> "/data/local/tmp/"`

Start Frida on the Android thrower using:

```bash
adb root
adb shell
/data/local/tmp/frida-server-16.3.3-android-arm64 &
```

Note the thrower device name for the thrower by running `frida-ls-devices`.
The exploit will default to the first USB-connected device, however this might
not be desired if there is more than one device connected via USB. For example,
the desired Android device from the list below is *emulator-5554*.

```console
$ frida-ls-devices
Id                                        Type    Name                    OS
----------------------------------------  ------  ----------------------  --------------
emulator-5554                             usb     Android Emulator 5554   Android 11
00008120-AC5747734D9A2596                 usb     iPhone                  iPhone OS 16.0
00008030-0015581A0C50802E                 usb     webrtc-vuln             iPhone OS 16.4
barebone                                  remote  GDB Remote Stub
socket                                    remote  Local Socket
```

## Throwing

Navigate to the `frida-scripts` directory and trigger the read and write
vulnerabilities using the following commands:

```shell
python3 trigger.py -D emulator-5554 -t read -n <target number>
# or
python3 trigger.py -D emulator-5554 -t write -n <target number>
```

# Part 2

Instructions for following along with
[Part 2](https://margin.re/2024/07/you-cant-spell-webrtc-without-rce-part-2/)
of the blog series.

## Building

Install the dependencies and set the `DEPOT_TOOLS` environment variable as
outlined in the beginning of Part 1's "Building" section.

### iOS

Create an [Apple Developer account](https://developer.apple.com/) that allows
for signing of compiled .ipa files. Update Xcode to recognize this account.

Set the `DEPOT_TOOLS` environment variable as outlined in Part 1 and run `make
build-ios-archive`. This will fetch Signal-iOS, download dependencies, patch
WebRTC, and recompile Signal-iOS with the injected vulnerabilities. Load the
resulting `Signal-iOS` project in Xcode and change the following project
settings.

In the `Signal` app project settings:
* Build Settings -> `SIGNAL_BUNDLEID_PREFIX`: change to a new prefix, preferably
one associated with the group/company of the Apple Developer account
* Target `Signal` -> Signing & Capabilities: change the `Team` profile to the
Apple Developer account or the account's company name. This is required for
Debug and Testable Release configurations
* Target `SignalNSE` -> Signing & Capabilities: change the `Team` profile to
the Apple Developer account or the account's company name. This is required for
Debug and Testable Release configurations
* Target `SignalShareExtension` -> Signing & Capabilities: change the `Team`
profile to the Apple Developer account or the account's company name. This is
required for Debug and Testable Release configurations
* Target `Signal` -> Signing & Capabilities -> Entitlements: delete the
Apple Pay, Communication Notifications, and Data Protection entitlements
* Do the same as above for the `SignalShareExtension` and `SignalNSE` targets

Edit the project scheme for Archiving to be Testable Release.

Set the target device to `Any iOS Device (arm64)` and build the program. Select
the Debugging distribution as the final output. Choose a storage location on
disk for the archived .ipa file.

### Android

Build the Android thrower as outlined in Part 1. No further modification
are necessary.

## Running

### Corellium

Register for a [Corellium](https://www.corellium.com/)
account and create the target iPhone device: iPhone
14 Pro running iOS 16.4 (20E247). Install the compiled application on the
virtualized device by dragging and dropping into the Apps pane after booting.
*Turn off Background Refresh in Settings -> General -> Background App Refresh ->
Signal and Disable Notifications in Settings -> Signal -> Notifications*.
Failing to perform these actions will prevent the device from registering a
phone number. Register a victim phone number and send a text message to the
attacking phone number so they are in one another's address book.

An alternative to Corellium is to jailbreak a real device to allow for
installation of the vulnerable app. This blog does not cover jailbreaking.

### Android Thrower

Perform the same tasks as outlined in Part 1 to boot the Android thrower device
with Frida-server running in the background.

## Throwing

### Fetching Target Files

Fetch the appropriate iOS ipsw using
[Blacktop's ipsw tool](https://github.com/blacktop/ipsw.git). For example,
fetch iOS 16.4 for the iPhone 14 Pro (using a
[list of device numbers](https://gist.github.com/adamawolf/3048717)
maintained by Adam Wolf):

```shell
ipsw download --device iPhone15,2 --build 20E247 ipsw
# downloads file iPhone15,2_16.4_20E247_Restore.ipsw
```

### Triggering RCE

Navigate to the `frida-scripts` directory and throw the payload using the
following command:

```shell
cd frida_spython3 exploit.py -l call.js,exploit.js -n <number> -D <emulator> \
    -c <path to iPhone15,2_16.4_20E247_Restore.ipsw> \
    -s <path to target Signal.ipa> \
    -g ./gadgets.json
```
