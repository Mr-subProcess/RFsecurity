#include "rfsec/frame_parser.hpp"

#include <cstddef>
#include <cstdint>
#include <span>

// Offline-only libFuzzer target. It only exercises the sample parser.
extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    (void)rfsec::frame::parse(std::span<const std::uint8_t>(data, size));
    return 0;
}
