#include "rfsec/frame_parser.hpp"

#include <array>
#include <cstdint>
#include <iostream>
#include <vector>

#define CHECK(condition) do { \
    if (!(condition)) { \
        std::cerr << "CHECK failed at " << __FILE__ << ':' << __LINE__ \
                  << ": " #condition << '\n'; \
        return 1; \
    } \
} while (false)

int main() {
    using rfsec::frame::ParseResult;

    CHECK(rfsec::frame::parse(std::span<const std::uint8_t>{}) == ParseResult::TooShort);

    const std::array<std::uint8_t, 4> short_header{0x52, 0x46, 1, 0};
    CHECK(rfsec::frame::parse(short_header) == ParseResult::TooShort);

    const std::array<std::uint8_t, 6> bad_magic{0, 0x46, 1, 0, 1, 0x42};
    CHECK(rfsec::frame::parse(bad_magic) == ParseResult::BadMagic);

    const std::array<std::uint8_t, 6> bad_version{0x52, 0x46, 2, 0, 1, 0x42};
    CHECK(rfsec::frame::parse(bad_version) == ParseResult::UnsupportedVersion);

    const std::array<std::uint8_t, 5> oversized{0x52, 0x46, 1, 0x04, 0x01};
    CHECK(rfsec::frame::parse(oversized) == ParseResult::PayloadTooLarge);

    const std::array<std::uint8_t, 6> mismatch{0x52, 0x46, 1, 0, 2, 0x42};
    CHECK(rfsec::frame::parse(mismatch) == ParseResult::LengthMismatch);

    const std::array<std::uint8_t, 7> valid{0x52, 0x46, 1, 0, 2, 0x41, 0x42};
    CHECK(rfsec::frame::parse(valid) == ParseResult::Ok);

    std::vector<std::uint8_t> max_valid(rfsec::frame::kHeaderSize + rfsec::frame::kMaxPayload, 0xA5);
    max_valid[0] = 0x52;
    max_valid[1] = 0x46;
    max_valid[2] = 1;
    max_valid[3] = static_cast<std::uint8_t>((rfsec::frame::kMaxPayload >> 8U) & 0xFFU);
    max_valid[4] = static_cast<std::uint8_t>(rfsec::frame::kMaxPayload & 0xFFU);
    CHECK(rfsec::frame::parse(max_valid) == ParseResult::Ok);

    std::vector<std::uint8_t> max_plus_one(rfsec::frame::kHeaderSize + rfsec::frame::kMaxPayload + 1U, 0xA5);
    max_plus_one[0] = 0x52;
    max_plus_one[1] = 0x46;
    max_plus_one[2] = 1;
    max_plus_one[3] = static_cast<std::uint8_t>(((rfsec::frame::kMaxPayload + 1U) >> 8U) & 0xFFU);
    max_plus_one[4] = static_cast<std::uint8_t>((rfsec::frame::kMaxPayload + 1U) & 0xFFU);
    CHECK(rfsec::frame::parse(max_plus_one) == ParseResult::PayloadTooLarge);

    std::cout << "All frame parser tests passed.\n";
    return 0;
}
