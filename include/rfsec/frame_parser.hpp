#pragma once

#include <cstddef>
#include <cstdint>
#include <span>

namespace rfsec::frame {

// Demonstration wire format (for the parser you own / a lab protocol):
//   0..1 : magic 'R','F'
//   2    : version (1)
//   3..4 : payload length, unsigned big-endian
//   5..  : payload
inline constexpr std::size_t kHeaderSize = 5;
inline constexpr std::size_t kMaxPayload = 1024;

enum class ParseResult {
    Ok,
    TooShort,
    BadMagic,
    UnsupportedVersion,
    PayloadTooLarge,
    LengthMismatch,
};

[[nodiscard]] constexpr const char* to_string(ParseResult value) noexcept {
    switch (value) {
        case ParseResult::Ok: return "ok";
        case ParseResult::TooShort: return "too_short";
        case ParseResult::BadMagic: return "bad_magic";
        case ParseResult::UnsupportedVersion: return "unsupported_version";
        case ParseResult::PayloadTooLarge: return "payload_too_large";
        case ParseResult::LengthMismatch: return "length_mismatch";
    }
    return "unknown";
}

[[nodiscard]] inline ParseResult parse(std::span<const std::uint8_t> bytes) noexcept {
    if (bytes.size() < kHeaderSize) return ParseResult::TooShort;
    if (bytes[0] != 0x52 || bytes[1] != 0x46) return ParseResult::BadMagic;
    if (bytes[2] != 1) return ParseResult::UnsupportedVersion;

    const std::size_t payload_len =
        (static_cast<std::size_t>(bytes[3]) << 8U) |
         static_cast<std::size_t>(bytes[4]);

    if (payload_len > kMaxPayload) return ParseResult::PayloadTooLarge;
    // payload_len is bounded before addition, so this expression cannot overflow.
    if (bytes.size() != kHeaderSize + payload_len) return ParseResult::LengthMismatch;
    return ParseResult::Ok;
}

} // namespace rfsec::frame
