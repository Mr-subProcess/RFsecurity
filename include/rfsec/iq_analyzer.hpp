#pragma once

#include <cstdint>
#include <filesystem>
#include <optional>

namespace rfsec {

struct IqAnalysisOptions {
    std::uint32_t fft_size = 4096; // power of two
    std::optional<double> sample_rate_hz;
    std::optional<double> center_frequency_hz;
    std::filesystem::path spectrum_csv;
};

struct IqAnalysisSummary {
    std::uint64_t file_bytes = 0;
    std::uint64_t complex_samples = 0;
    std::uint64_t fft_windows = 0;
    double mean_i = 0.0;
    double mean_q = 0.0;
    double rms_i = 0.0;
    double rms_q = 0.0;
    double rms_component = 0.0;
    double rms_dbfs = 0.0;
    double peak_magnitude = 0.0;
    std::uint64_t clipped_components = 0;
    std::uint64_t total_components = 0;
};

// Reads raw HackRF IQ8: interleaved signed 8-bit I,Q. Does not load the full
// capture into memory. When sample_rate_hz is supplied, also computes an FFT
// spectrum and optionally writes it as CSV.
int analyze_iq_file(const std::filesystem::path& input,
                    const IqAnalysisOptions& options,
                    IqAnalysisSummary* summary_out = nullptr);

} // namespace rfsec
