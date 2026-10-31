#pragma once

#include <cstdint>
#include <filesystem>

namespace rfsec {

struct CaptureOptions {
    std::uint64_t frequency_hz = 0;
    std::uint32_t sample_rate_sps = 2'000'000;
    std::uint32_t duration_seconds = 10;
    std::uint32_t lna_gain_db = 16;
    std::uint32_t vga_gain_db = 20;
    std::filesystem::path output_file;
};

int capture_hackrf_rx(const CaptureOptions& options);
int capture_capability_status();

} // namespace rfsec
