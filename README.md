# RFSEC 0.6.0 — HackRF + Cellular Assurance Toolkit

**Project:** DRNC Quantum Systems  |  **Maintainer:** Oğuz Kağan Sayın

**Project owner:** Oğuz Kağan Sayın  
**Language:** C++20  
**Radio interface:** Great Scott Gadgets `libhackrf` RX-only (optional)  
**Android interface:** Android Debug Bridge (`adb`) for local, user-confirmed device actions

RFSEC combines receive-only HackRF capture, offline parser-security testing, and a real Android-device controller. Android integration uses ADB over USB to inspect basic device properties and open the handset's native dialer or SMS composer. RFSEC does not automate call placement or message sending.

## Safety and scope

This project intentionally contains **no TX, jammer, rogue-cell/base-station impersonation, forced handset attach, cellular interception, packet injection, spoofed caller identity, or mass messaging/calling path**. HackRF support is RX-only. Mutation cases are saved to disk and are not sent over RF. Android call/SMS commands only open the native UI on one selected, ADB-authorized handset; the user must review and confirm the action on that device. Use only devices, SIMs, recipients and networks for which you have permission. RFSEC is not a generic protocol decoder: demodulation and protocol-specific decoding are separate, protocol-dependent stages.

## Version 0.6.0 features

### Radio capture (optional `libhackrf`)

- HackRF One RX capture to raw interleaved signed 8-bit I/Q (`.iq8`).
- Configurable center frequency, sample rate, capture duration, LNA gain and VGA gain.
- Bounded producer/consumer queue to avoid unbounded memory growth when disk I/O falls behind.
- Explicit reporting of dropped bytes; a lossy capture returns a warning status.
- JSON sidecar metadata (`capture.iq8.json`) recording capture settings and dropped-byte count.
- Ctrl+C / SIGTERM graceful stop path.


### Real Android device control and posture auditing (ADB)

- Lists Android devices authorized for USB debugging (`rfsec device list`).
- Inspects non-unique device and radio properties: model, manufacturer, Android version, build fingerprint, SIM state, carrier label and reported radio technology.
- Performs a read-only Android security-posture audit: patch date, SELinux mode, storage-encryption state, Verified Boot state, bootloader lock, ADB/developer options and airplane-mode setting.
- Provides a local, read-only RAN/core configuration linter for wide binds, plaintext management endpoints, disabled TLS verification, disabled authentication, empty/default secrets and risky file permissions.
- Exports a structured JSON audit report (`device audit --out report.json`). The report omits IMEI, IMSI, MSISDN, contacts, SMS contents and call history.
- Opens the selected phone's native dialer for a manually confirmed one-to-one test call (`call-ui`). It does **not** place the call automatically.
- Opens the selected phone's native SMS composer addressed to one E.164 destination (`sms-ui`). It does **not** compose, send or bulk-send messages.
- Uses argument-vector process execution (no host-side shell command construction), strict device-serial validation and E.164 destination validation.
- Does not collect IMEI, IMSI, phonebook, SMS inbox, call history, authentication keys or subscriber credentials.
- Interactive menu: `rfsec telecom menu`, with device inspection, posture audit, per-device call/SMS UI launch, passive RF capture guidance and private-network assessment checklist.

### Passive cellular/RF/comms security monitors (v0.6.0)

- **Cell anomaly audit:** evaluates exported, non-subscriber cell observations (RAT, MCC/MNC, TAC, cell identity, PCI, channel number, RSRP/RSRQ and an externally reported ciphering state). Supports an optional expected-PLMN allowlist and flags identity churn, PCI reuse, unapproved PLMN observations, unusually strong signals and an externally reported disabled-ciphering state. It does not force handset attachment, decode subscriber identifiers or transmit.
- **RF interference indicators:** streams previously captured IQ8 files in bounded FFT windows and reports RMS level, spectral flatness, peak-to-median ratio, occupied-bin fraction and clipping. Findings are descriptive indicators only; RFSEC cannot conclude that jamming occurred from these metrics alone. No noise generator, TX API or signal suppressor exists.
- **SMS/PBX event audit:** evaluates sanitized SMSC/PBX gateway event logs for unverified origins, untrusted routes, event-rate spikes, high recipient fan-out and failures. The schema accepts only 16–64 character hexadecimal HMAC tokens instead of phone numbers and never accepts message/call content. It audits existing logs; it cannot send SMS or initiate calls.
- Three dedicated C++ APIs are exposed in paired `.hpp`/`.cpp` files: `CellAnomalyDetector`, `InterferenceMonitor`, and `CommsGatewayAuditor`.
- New interactive menu entries and CLI commands: `telecom cell-audit`, `telecom rf-audit`, and `telecom comms-audit`.

### IQ analysis (no HackRF required)

- Streaming file reader; does not load the complete capture into RAM.
- I/Q mean, per-channel RMS, combined RMS, peak complex magnitude and near-full-scale component counts.
- Optional radix-2 FFT with periodic Hann window and averaged power bins.
- Top-bin summary and optional CSV spectrum export.
- Optional center-frequency annotation for frequency-axis values.

The spectrum values are digital `dBFS/bin` estimates, not calibrated antenna-port power, field strength, or a substitute for a calibrated measurement receiver.

### Offline parser security testing

- Deterministic mutation corpus generation when `--rng-seed` is set.
- Mutation types: bitflip, truncate, extend, duplicate, zero, insert, erase, boundary-value replacement and local byte shuffle. An opt-in `length` mutation targets the sample frame format's two-byte declared payload length.
- Configurable generated-case size (hard maximum 1 MiB per file), a 512 MiB aggregate corpus safety cap and manifest CSV.
- A sample length-checked frame parser and `validate` command.
- Unit tests and an optional libFuzzer target.
- CMake option for AddressSanitizer + UndefinedBehaviorSanitizer builds.

## Requirements

- CMake 3.20+
- C++20 compiler (GCC 11+, Clang 13+ recommended)
- Threads
- Optional radio capture: HackRF host tools and `libhackrf` development headers/library, discoverable through `pkg-config` as `libhackrf`
- Android controller: Android Platform Tools (`adb`), an Android phone with USB debugging enabled and the user-approved ADB authorization prompt (the ADB controller currently targets Linux/macOS)
- Optional coverage-guided fuzzing: Clang with libFuzzer

On Debian/Ubuntu, package names commonly include `libhackrf-dev`, `hackrf`, `pkg-config`, and `libusb-1.0-0-dev`. Package availability can vary by distribution release.

## Build

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
ctest --test-dir build --output-on-failure
```

CMake always builds the offline tool. If `pkg-config --modversion libhackrf` succeeds, it also enables hardware RX capture. Otherwise `rfsec capture` prints a clear capability message while the offline commands remain functional.

Optional sanitizers:

```bash
cmake -S . -B build-asan \
  -DCMAKE_BUILD_TYPE=Debug \
  -DRFSEC_ENABLE_SANITIZERS=ON
cmake --build build-asan -j
ctest --test-dir build-asan --output-on-failure
```

## Android device setup

1. Install Android Platform Tools and make sure `adb` is available on `PATH`.
2. On the Android test phone, enable Developer options and USB debugging.
3. Connect the phone by USB and accept the debugging authorization prompt on the phone.
4. Check the device:

```bash
./build/rfsec device list
./build/rfsec device inspect --serial YOUR_ADB_SERIAL
./build/rfsec device audit --serial YOUR_ADB_SERIAL --out android-audit.json
```

The `inspect` and `audit` commands intentionally avoid unique subscriber/device identifiers such as IMEI and IMSI. The audit is a read-only posture check, not a full mobile penetration test; vendor-specific controls may be unavailable through non-root ADB.

### Operator-owned RAN/core configuration audit

RFSEC includes a passive, local-file linter for configuration files from a RAN or mobile-core deployment you own or are explicitly authorized to assess. It does not connect to the network or send packets. The heuristic checks include:

- listeners apparently bound to all interfaces (`0.0.0.0` / `::`);
- management/service endpoints configured with plaintext HTTP;
- TLS peer/certificate verification apparently disabled;
- authentication explicitly disabled;
- empty or well-known default/test secret values (secret values are never printed);
- configuration files writable by other local users or world-readable;
- debug/trace logging which may expose sensitive operational data.

Example:

```bash
./build/rfsec telecom config-audit \
  --file /path/to/your/ran-or-core-config.yaml \
  --out ran-config-audit.json
```

### Passive cellular observation audit

CSV schema (one row per externally collected cell observation):

```text
timestamp_ms,rat,mcc,mnc,tac,cell_id,pci,arfcn,rsrp_dbm,rsrq_db,ciphering
```

Example:

```bash
./build/rfsec telecom cell-audit \
  --in examples/cell_observations.csv \
  --allow-plmn 286-01 \
  --out cell-findings.csv
```

The input must be exported from a lawful field-test/diagnostic source. Cell identity and PCI reuse can be legitimate due to mobility and planned frequency reuse. A finding is a lead for validation, not proof of a rogue base station. The ciphering field is supplied metadata and must be corroborated with trusted network diagnostics.

### Passive RF interference indicators

```bash
./build/rfsec telecom rf-audit \
  --in lab.iq8 --rate 2000000 --center 433920000 \
  --fft-size 2048 --out rf-quality-findings.csv
```

The monitor reads saved IQ8 captures only. Metrics such as spectral flatness, clipping and elevated broadband energy are not unique to jamming; receiver gain, local emitters, multipath and front-end overload can produce similar patterns.

### Sanitized SMS/PBX gateway security audit

Expected CSV columns:

```text
timestamp_ms,event_type,direction,actor_token,peer_token,auth_status,route_status,result
```

`actor_token` and `peer_token` must be truncated/full hexadecimal keyed-HMAC identifiers, 16–64 characters. Do not place raw phone numbers, IMSI, IMEI or message text in this file.

```bash
./build/rfsec telecom comms-audit \
  --in examples/gateway_events.csv --out gateway-findings.csv \
  --window-sec 60 --max-events 20 --max-fanout 10
```

The checker is intentionally heuristic and format-agnostic. Review each finding against the vendor's supported topology and configuration schema; no finding is not proof of security. Use a sanitized copy if you do not want to expose secrets to the local test process. The JSON report includes finding code, severity, line number and a generic summary, not the original line or secret value. Exit status is `1` when HIGH findings are present, `0` when no HIGH findings are found, and `2` for input/output errors.

A deliberately insecure fixture is included for testing the linter:

```bash
./build/rfsec telecom config-audit \
  --file examples/ran_config_audit_demo.yaml \
  --out ran-demo-report.json
```

### User-confirmed test call and SMS

Open the Android dialer with one test recipient:

```bash
./build/rfsec device call-ui --serial YOUR_ADB_SERIAL --number +905321234567
```

Open the Android SMS composer for one test recipient:

```bash
./build/rfsec device sms-ui --serial YOUR_ADB_SERIAL --number +905321234567
```

These commands launch Android's standard UI only. The user must review the number and manually tap Call or Send. They do not spoof a sender/caller, bypass the carrier, force network attachment, or send messages automatically. Test only with a recipient and subscription for which you have permission.

Run the same audit through the telecom namespace:

```bash
./build/rfsec telecom audit --serial YOUR_ADB_SERIAL --out telecom-audit.json
```

Open the interactive telecom menu:

```bash
./build/rfsec telecom menu
```

## CLI reference

### 1. Check build capabilities

```bash
./build/rfsec status
./build/rfsec version
```

### 2. Receive a short IQ capture

```bash
./build/rfsec capture \
  --freq 433920000 \
  --rate 2000000 \
  --seconds 8 \
  --lna 16 \
  --vga 20 \
  --out lab.iq8
```

Validations enforced by RFSEC:

- Frequency: 1 MHz to 6 GHz (the device's documented tuning range).
- Sample rate: 2 to 20 MS/s.
- LNA gain: 0 to 40 dB in 8 dB increments.
- VGA gain: 0 to 62 dB in 2 dB increments.
- Duration: 1 to 3600 seconds.

Capture generates two files:

```text
lab.iq8        # raw interleaved signed 8-bit I,Q sample bytes
lab.iq8.json   # settings and capture-integrity metadata
```

The file contains no embedded header. Preserve the sidecar metadata with the IQ file.

### 3. Analyze IQ statistics and spectrum

Basic time-domain summary:

```bash
./build/rfsec analyze --in lab.iq8
```

FFT and frequency-axis report:

```bash
./build/rfsec analyze \
  --in lab.iq8 \
  --rate 2000000 \
  --center 433920000 \
  --fft-size 4096 \
  --csv lab-spectrum.csv
```

FFT size must be a power of two from 256 through 65536. The implementation processes one FFT block at a time and averages power spectra across complete windows. A final partial window contributes to time-domain statistics but not to the FFT average.

### 4. Generate a reproducible offline test corpus

```bash
./build/rfsec mutate \
  --seed examples/seed_frame.bin \
  --out corpus \
  --count 500 \
  --kind all \
  --rng-seed 42 \
  --max-size 4096
```

Available mutation kinds:

| Kind | Test objective |
|---|---|
| `bitflip` | Bit-level corruption and validation paths |
| `truncate` | Incomplete headers and payloads |
| `extend` | Unexpected trailing bytes and overlong inputs |
| `duplicate` | Repeated ranges and duplicate-field handling |
| `zero` | Zero-filled values and empty-like fields |
| `insert` | New bytes inserted at arbitrary offsets |
| `erase` | Contiguous byte-range removal |
| `boundary` | Common byte boundary values (`00`, `01`, `7f`, `80`, `fe`, `ff`) |
| `shuffle` | Local ordering and parser-state assumptions |
| `length` | RFSEC sample-frame only: declared length values 0, 1, 1023, 1024, 1025, 2048, 4096 and 65535 |
| `all` | Random selection from the generic mutation types above (does not assume a specific length-field layout) |

A `manifest.csv` file is created in the output directory. Setting `--rng-seed` makes the corpus repeatable. Omitting it selects a random seed.

### 5. Validate the example frame format

```bash
./build/rfsec validate --in examples/seed_frame.bin
```

Example wire format:

```text
+---------+---------+---------+----------------------+----------------+
| Magic   | Version | Length  | Payload              |                |
| 2 bytes | 1 byte  | 2 bytes | 0..1024 bytes        |                |
+---------+---------+---------+----------------------+----------------+
```

The parser verifies minimum header length, magic, version, payload upper bound and exact frame length before accepting the frame. The `length` mutation is intentionally format-specific and only modifies byte offsets 3–4 when the sample-frame magic/version match; use the other generic mutations for unrelated protocols.

### 6. Coverage-guided parser fuzzing

```bash
mkdir -p build/fuzz-corpus
clang++ -std=c++20 -g -O1 \
  -fsanitize=fuzzer,address,undefined \
  -Iinclude examples/libfuzzer_target.cpp \
  -o build/frame_parser_fuzz

./build/frame_parser_fuzz -max_len=4096 build/fuzz-corpus
```

For your own parser, replace the sample parser call with the parser implementation you are authorized to test, preserving its documented input contract. Run the parser in an isolated test process/container when it is not trusted.

## Recommended workflow

1. Capture RF in a lawful and controlled receive environment.
2. Apply a protocol-specific demodulator/decoder in a lab; RFSEC does not automatically infer arbitrary modulation or framing.
3. Export a decoded frame as a binary seed file.
4. Generate a mutation corpus to exercise the parser's negative paths.
5. Run the parser with ASan/UBSan or libFuzzer.
6. Minimize a failing test case and preserve it as a regression input.
7. Fix length arithmetic, integer conversions, state handling and bounds checks; then rerun the regression corpus.

## Hardware cautions

HackRF One is a half-duplex SDR with a documented 1 MHz–6 GHz tuning range, 2–20 MS/s sample rates and 8-bit I/Q. The documented maximum RF input power is -5 dBm. Use front-end attenuation/protection and do not connect unknown or high-power RF sources directly. Check applicable local rules before receiving or recording signals.

## Explicitly unsupported telecom attack functions

RFSEC does not create or operate an impersonated carrier base station, induce nearby phones to attach, jam or interrupt other cells, intercept subscriber traffic, extract subscriber secrets, spoof caller identity, or broadcast calls/SMS to nearby handsets. Those operations can disrupt public communications and expose private communications. Authorized cellular-network assurance should be performed through the private-network operator's documented management/test interfaces and controlled test subscriptions; the RFSEC Android controller is for per-device, user-confirmed call/SMS workflows only.

## Project structure

```text
rfsec_hackrf/
├── CMakeLists.txt
├── README.md
├── CHANGELOG.md
├── docs/
│   ├── ARCHITECTURE.md
│   ├── SECURITY_MODEL.md
│   ├── TELECOM_MONITORS.md
│   └── API_REFERENCES.md
├── include/rfsec/
│   ├── android_device.hpp
│   ├── cellular_anomaly.hpp
│   ├── comms_audit.hpp
│   ├── frame_parser.hpp
│   ├── hackrf_capture.hpp
│   ├── interference_monitor.hpp
│   ├── iq_analyzer.hpp
│   ├── mutator.hpp
│   └── telecom_config_audit.hpp
├── src/
│   ├── android_device.cpp
│   ├── cellular_anomaly.cpp
│   ├── comms_audit.cpp
│   ├── hackrf_capture.cpp
│   ├── interference_monitor.cpp
│   ├── iq_analyzer.cpp
│   ├── main.cpp
│   ├── mutator.cpp
│   ├── telecom_config_audit.cpp
│   └── capture_stub.cpp
├── examples/
│   ├── cell_observations.csv
│   ├── gateway_events.csv
│   ├── seed_frame.bin
│   ├── frame_parser_demo.cpp
│   ├── libfuzzer_target.cpp
│   └── ran_config_audit_demo.yaml
├── tests/
│   ├── test_android_device.cpp
│   ├── test_cellular_anomaly.cpp
│   ├── test_comms_audit.cpp
│   ├── test_interference_monitor.cpp
│   ├── test_parser.cpp
│   └── test_telecom_config_audit.cpp
└── scripts/
    └── build.sh
```
