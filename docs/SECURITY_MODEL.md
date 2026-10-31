# RFSEC security model (0.6.0)

## Included capabilities

- Passive HackRF RX capture only.
- Local IQ-file analysis and spectrum export.
- Local frame validation and offline mutation corpus creation.
- Local parser testing and fuzzing.
- ADB listing and limited inspection of an explicitly authorized Android handset.
- Read-only Android security-posture audit with JSON export.
- Read-only, local-file RAN/core configuration heuristic audit with JSON export.
- User-confirmed launch of the native dialer or SMS composer for one destination at a time.
- Passive cell identity anomaly analysis over exported non-subscriber metadata.
- Receive-only IQ8 interference-indicator analysis.
- Sanitized SMS/PBX event-log auditing using hexadecimal HMAC tokens.

## Deliberately excluded capabilities

- RF transmission, jamming, denial of service or rapid RX/TX switching for cellular disruption.
- Rogue or impersonated carrier/base-station operation, forced handset attachment or downgrade inducement.
- Cellular traffic interception, subscriber identity/credential harvesting or SMS/call interception.
- Spoofed caller identity, unsolicited/bulk SMS or calls, or automatic call/message submission.
- Cellular packet replay/injection and exploit delivery to third-party radios, receivers or controllers.

## Android integration boundary

The ADB controller uses `execvp` with a fixed argument vector; it does not build a host shell command from user input. Device serials are restricted to a conservative character set. Destination numbers must be E.164 (`+` followed by 7–15 digits). The dialer uses `ACTION_DIAL`, not `ACTION_CALL`. SMS uses `ACTION_SENDTO` with an `smsto:` URI and leaves composition and sending to the handset user.

Device inspection and posture auditing read general build, security and radio properties. They do not request or read IMEI, IMSI, subscriber keys, address book, SMS inbox or call history. ADB authorization must be approved locally on the handset.

## RAN/core configuration audit boundary

The RAN/core linter performs static checks on a local file only. It is format-agnostic and heuristic: false positives and false negatives are possible. Never treat an empty finding list as proof of security. Compare findings with the network vendor's deployment guide and assess the management plane through the operator's approved maintenance process. Avoid including unredacted production credentials in files shared with third parties.

## Threat model for parser testing

The sample parser accepts untrusted byte arrays. It must reject malformed input without reading outside the supplied span, allocating unbounded memory, or trusting a declared length before checking it. Tests should include malformed headers, boundary lengths, truncated payloads, duplicate/reordered fields and large-but-bounded input.

RFSEC's sample parser is illustrative. A real protocol parser may have stateful semantics, cryptographic authentication, checksums, sequence windows and application-specific constraints. Those must be implemented from the relevant protocol specification rather than guessed by a generic mutation engine.

## Telecom monitor data boundaries

The cell auditor accepts broadcast/cell metadata only; it does not accept IMSI, IMEI, MSISDN, authentication keys or user payloads. The interference monitor reads saved IQ8 files, not live TX buffers. The gateway auditor accepts only schema-limited event logs and opaque HMAC tokens; it does not contact SMSCs, PBXs, handsets or carriers. The monitors are read-only and cannot send or inject traffic.
