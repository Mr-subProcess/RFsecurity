#pragma once

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace rfsec::telecom {

struct InterferenceOptions {
    std::uint32_t fft_size = 2048;
    double sample_rate_hz = 0.0;
    double center_frequency_hz = 0.0;
    double flatness_warning_threshold = 0.78;
    double clipping_warning_ratio = 0.01;
};

struct InterferenceWindow {
    std::uint64_t window_index = 0;
    double rms_dbfs = 0.0;
    double spectral_flatness = 0.0;
    double peak_to_median_db = 0.0;
    double occupied_fraction = 0.0;
    double clipping_fraction = 0.0;
    std::string assessment;
};

struct InterferenceReport {
    std::uint64_t samples = 0;
    std::uint64_t fft_windows = 0;
    std::vector<InterferenceWindow> windows;
};

class InterferenceMonitor {
public:
    explicit InterferenceMonitor(InterferenceOptions options = {}) : options_(options) {}
    // Passive analysis of a previously captured IQ8 file; no RF TX path exists.
    int analyze(const std::filesystem::path& input_iq8,
                const std::filesystem::path& output_csv = {},
                InterferenceReport* report_out = nullptr) const;
private:
    InterferenceOptions options_;
};

// Convenience wrapper for one-shot CLI use.
int audit_iq_interference(const std::filesystem::path& input_iq8,
                          const InterferenceOptions& options,
                          const std::filesystem::path& output_csv = {},
                          InterferenceReport* report_out = nullptr);

} // namespace rfsec::telecom
