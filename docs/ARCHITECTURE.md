# RFSEC architecture (0.6.0)

```text
                         +--------------------------+
                         |        rfsec CLI          |
                         +------------+-------------+
                                      |
       +------------------------------+------------------------------+
       |                |              |              |               |
 +-----v------+  +------v------+ +-----v------+ +-----v----------+ +--v-----------+
 | HackRF RX  |  | IQ Analyzer | | Corpus     | | Android ADB    | | RAN/Core     |
 | (optional) |  | (offline)   | | Maker      | | Device Audit   | | Config Audit |
 +-----+------+  +------+------+ +-----+------+ +-----+----------+ +------+-------+
       |                |              |              |                   |
     IQ8/JSON        FFT/CSV       mutated files   JSON posture       JSON findings
       |                |              |              |                   |
       +----------------+--------------+--------------+-------------------+
                                      |
                           Local parser/security tests
```

## Hardware boundary

`rfsec_radio` is the only library that includes `hackrf.h`. It uses RX setup/streaming APIs and writes captured bytes to a local file. If CMake cannot find `libhackrf`, CMake substitutes `capture_stub.cpp`; the rest of the project still builds. No RF transmit implementation is present.

## Android device boundary

`android_device.cpp` uses ADB through POSIX `fork`/`execvp`, with arguments passed as a vector. It lists authorized devices, inspects general non-unique properties, performs a read-only security-posture audit, opens `ACTION_DIAL`, or opens `ACTION_SENDTO` for one E.164 destination. Calls and messages are completed by the handset user. The module does not interact with modem firmware, baseband diagnostic ports or carrier network signaling.

The posture report checks Android release/build information, security patch date, SELinux mode, encryption state, Verified Boot, bootloader lock, ADB/developer settings and non-identifying radio context. It does not collect unique subscriber identifiers or user communications.

## RAN/core configuration audit boundary

`telecom_config_audit.cpp` is a local-file-only heuristic linter. It reads a bounded configuration file and checks for broadly exposed listener binds, plaintext HTTP endpoints, disabled TLS verification, disabled authentication, empty/default secrets, risky local file permissions and debug logging. It does not connect to a host, probe a port, log in, send packets, or exploit a service. Findings contain generic descriptions and line numbers; original config lines and secret values are never emitted. Vendor-specific topology and schema must be reviewed by an engineer; heuristic clean output is not a security certification.

## IQ analysis boundary

`rfsec_core` reads raw IQ8 files in bounded blocks. Time-domain statistics include every complete I/Q pair. If FFT mode is enabled, only complete FFT windows are transformed; a trailing partial window still contributes to sample statistics. The FFT uses a periodic Hann window and computes mean per-bin power across windows.

## Parser test boundary

The built-in parser is an intentionally small example wire format, not a universal radio-protocol parser. `rfsec mutate` writes changed byte vectors to disk only. The `length` mutation is specific to the example format; general mutation types do not assume a fixed protocol layout.

## Telecom monitoring boundary (0.6.0)

The telecom monitoring modules consume exported cell metadata, saved IQ8 files and sanitized gateway logs. They are not a base-station implementation, RF jammer, IMSI catcher or OTA SMS/call sender. Cell anomaly reports are heuristic and require independent validation. Gateway logs must use keyed HMAC tokens rather than phone numbers.
