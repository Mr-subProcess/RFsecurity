#include "rfsec/interference_monitor.hpp"

#include <cassert>
#include <cmath>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <numbers>

int main() {
    using namespace rfsec::telecom;
    const auto path = std::filesystem::temp_directory_path() / "rfsec_iq_interference_test.iq8";
    constexpr std::size_t n = 256;
    {
        std::ofstream out(path, std::ios::binary);
        for (std::size_t i = 0; i < n; ++i) {
            const double phase = 2.0 * std::numbers::pi * 9.0 * static_cast<double>(i) / static_cast<double>(n);
            const auto iv = static_cast<std::int8_t>(std::lround(60.0 * std::cos(phase)));
            const auto qv = static_cast<std::int8_t>(std::lround(60.0 * std::sin(phase)));
            out.put(static_cast<char>(static_cast<std::uint8_t>(iv)));
            out.put(static_cast<char>(static_cast<std::uint8_t>(qv)));
        }
    }
    InterferenceOptions options; options.fft_size = n; options.sample_rate_hz = 1'000'000.0;
    InterferenceReport report;
    InterferenceMonitor monitor(options);
    const int rc = monitor.analyze(path, {}, &report);
    assert(rc == 0);
    assert(report.samples == n);
    assert(report.fft_windows == 1);
    assert(report.windows.size() == 1);
    std::filesystem::remove(path);
    std::cout << "passive interference tests passed\n";
}
