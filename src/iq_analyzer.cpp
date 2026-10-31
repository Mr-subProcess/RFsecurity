#include "rfsec/iq_analyzer.hpp"

#include <algorithm>
#include <bit>
#include <cmath>
#include <complex>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <numbers>
#include <numeric>
#include <string>
#include <vector>

namespace rfsec {
namespace {

using Complex = std::complex<double>;

[[nodiscard]] bool is_power_of_two(std::uint32_t n) {
    return n >= 2 && (n & (n - 1U)) == 0;
}

void fft_in_place(std::vector<Complex>& values) {
    const std::size_t n = values.size();
    for (std::size_t i = 1, j = 0; i < n; ++i) {
        std::size_t bit = n >> 1U;
        for (; (j & bit) != 0; bit >>= 1U) j ^= bit;
        j ^= bit;
        if (i < j) std::swap(values[i], values[j]);
    }

    for (std::size_t length = 2; length <= n; length <<= 1U) {
        const double angle = -2.0 * std::numbers::pi / static_cast<double>(length);
        const Complex step(std::cos(angle), std::sin(angle));
        for (std::size_t base = 0; base < n; base += length) {
            Complex twiddle(1.0, 0.0);
            const std::size_t half = length / 2;
            for (std::size_t j = 0; j < half; ++j) {
                const Complex even = values[base + j];
                const Complex odd = values[base + j + half] * twiddle;
                values[base + j] = even + odd;
                values[base + j + half] = even - odd;
                twiddle *= step;
            }
        }
        if (length == n) break; // avoids unsigned shift overflow at the upper bound
    }
}

struct Accumulator {
    long double sum_i = 0;
    long double sum_q = 0;
    long double sum_i2 = 0;
    long double sum_q2 = 0;
    double peak_magnitude = 0;
    std::uint64_t samples = 0;
    std::uint64_t clipped = 0;
};

void add_sample(Accumulator& acc, std::int8_t i8, std::int8_t q8) {
    const double i = static_cast<double>(i8);
    const double q = static_cast<double>(q8);
    acc.sum_i += i;
    acc.sum_q += q;
    acc.sum_i2 += i * i;
    acc.sum_q2 += q * q;
    acc.peak_magnitude = std::max(acc.peak_magnitude, std::hypot(i, q));
    if (std::abs(i) >= 127.0) ++acc.clipped;
    if (std::abs(q) >= 127.0) ++acc.clipped;
    ++acc.samples;
}

} // namespace

int analyze_iq_file(const std::filesystem::path& input_path,
                    const IqAnalysisOptions& options,
                    IqAnalysisSummary* summary_out) {
    if (options.sample_rate_hz && (!std::isfinite(*options.sample_rate_hz) || *options.sample_rate_hz <= 0.0)) {
        std::cerr << "Sample rate must be a positive finite number.\n";
        return 2;
    }
    if (options.center_frequency_hz && (!std::isfinite(*options.center_frequency_hz) || *options.center_frequency_hz < 0.0)) {
        std::cerr << "Center frequency must be a non-negative finite number.\n";
        return 2;
    }
    if (options.sample_rate_hz && !is_power_of_two(options.fft_size)) {
        std::cerr << "FFT size must be a power of two (256..65536).\n";
        return 2;
    }
    if (options.sample_rate_hz && (options.fft_size < 256 || options.fft_size > 65536)) {
        std::cerr << "FFT size must be between 256 and 65536.\n";
        return 2;
    }

    std::error_code ec;
    const auto file_size = std::filesystem::file_size(input_path, ec);
    if (ec) {
        std::cerr << "Cannot stat IQ file: " << ec.message() << '\n';
        return 2;
    }
    if (file_size < 2 || (file_size % 2U) != 0U) {
        std::cerr << "Raw IQ8 file must contain complete interleaved I/Q byte pairs.\n";
        return 2;
    }

    std::ifstream input(input_path, std::ios::binary);
    if (!input) {
        std::cerr << "Cannot open IQ file: " << input_path << '\n';
        return 2;
    }

    const std::size_t fft_size = options.fft_size;
    std::vector<std::uint8_t> raw(fft_size * 2U);
    std::vector<Complex> spectrum(fft_size);
    std::vector<double> power_sum(options.sample_rate_hz ? fft_size : 0U, 0.0);
    std::vector<double> window(fft_size);
    double window_sum = 0.0;
    if (options.sample_rate_hz) {
        for (std::size_t n = 0; n < fft_size; ++n) {
            // Periodic Hann window, appropriate for block FFT analysis.
            window[n] = 0.5 - 0.5 * std::cos(2.0 * std::numbers::pi * static_cast<double>(n) /
                                             static_cast<double>(fft_size));
            window_sum += window[n];
        }
    }

    Accumulator acc;
    std::uint64_t fft_windows = 0;
    for (;;) {
        input.read(reinterpret_cast<char*>(raw.data()), static_cast<std::streamsize>(raw.size()));
        const auto got = static_cast<std::size_t>(input.gcount());
        if (got == 0) break;
        if ((got % 2U) != 0U) {
            std::cerr << "Unexpected partial I/Q sample at end of file.\n";
            return 2;
        }
        const std::size_t samples_in_block = got / 2U;
        const bool full_fft_block = options.sample_rate_hz && samples_in_block == fft_size;
        for (std::size_t n = 0; n < samples_in_block; ++n) {
            const auto i8 = std::bit_cast<std::int8_t>(raw[2U * n]);
            const auto q8 = std::bit_cast<std::int8_t>(raw[2U * n + 1U]);
            add_sample(acc, i8, q8);
            if (full_fft_block) {
                spectrum[n] = Complex(static_cast<double>(i8) * window[n],
                                       static_cast<double>(q8) * window[n]);
            }
        }
        if (full_fft_block) {
            fft_in_place(spectrum);
            const double denominator = window_sum * window_sum * 127.0 * 127.0;
            for (std::size_t k = 0; k < fft_size; ++k) {
                power_sum[k] += std::norm(spectrum[k]) / denominator;
            }
            ++fft_windows;
        }
    }

    IqAnalysisSummary summary;
    summary.file_bytes = file_size;
    summary.complex_samples = acc.samples;
    summary.fft_windows = fft_windows;
    summary.mean_i = static_cast<double>(acc.sum_i / acc.samples);
    summary.mean_q = static_cast<double>(acc.sum_q / acc.samples);
    summary.rms_i = std::sqrt(static_cast<double>(acc.sum_i2 / acc.samples));
    summary.rms_q = std::sqrt(static_cast<double>(acc.sum_q2 / acc.samples));
    summary.rms_component = std::sqrt((summary.rms_i * summary.rms_i + summary.rms_q * summary.rms_q) / 2.0);
    summary.rms_dbfs = summary.rms_component > 0.0
        ? 20.0 * std::log10(summary.rms_component / 127.0)
        : -std::numeric_limits<double>::infinity();
    summary.peak_magnitude = acc.peak_magnitude;
    summary.clipped_components = acc.clipped;
    summary.total_components = acc.samples * 2U;

    std::cout << std::fixed << std::setprecision(4)
              << "RFSEC IQ8 analysis\n"
              << "  File:                 " << input_path << '\n'
              << "  File bytes:           " << summary.file_bytes << '\n'
              << "  Complex samples:      " << summary.complex_samples << '\n'
              << "  Mean I / Q:           " << summary.mean_i << " / " << summary.mean_q << '\n'
              << "  RMS I / Q:            " << summary.rms_i << " / " << summary.rms_q << " counts\n"
              << "  Combined RMS:         " << summary.rms_component << " counts\n"
              << "  RMS level:            " << summary.rms_dbfs << " dBFS (component-normalized)\n"
              << "  Peak complex magnitude:" << summary.peak_magnitude << " counts\n"
              << "  Near-full-scale comps:" << summary.clipped_components << " / " << summary.total_components << '\n';

    if (options.sample_rate_hz) {
        if (fft_windows == 0) {
            std::cout << "  Spectrum:              skipped (capture shorter than one FFT window)\n";
        } else {
            std::vector<std::size_t> order(fft_size);
            std::iota(order.begin(), order.end(), 0U);
            std::sort(order.begin(), order.end(), [&](std::size_t a, std::size_t b) {
                return power_sum[a] > power_sum[b];
            });
            std::cout << "  FFT windows:           " << fft_windows << " (Hann, " << fft_size << " points)\n"
                      << "  Strongest bins (approx.):\n";
            for (std::size_t rank = 0; rank < std::min<std::size_t>(5, order.size()); ++rank) {
                const auto k = order[rank];
                const auto signed_bin = (k < fft_size / 2U)
                    ? static_cast<double>(k)
                    : static_cast<double>(k) - static_cast<double>(fft_size);
                const double offset = signed_bin * *options.sample_rate_hz / static_cast<double>(fft_size);
                const double center = options.center_frequency_hz.value_or(0.0);
                const double dbfs = 10.0 * std::log10(std::max(power_sum[k] / static_cast<double>(fft_windows), 1e-30));
                std::cout << "    " << std::setw(2) << (rank + 1) << ". bin=" << k
                          << " offset=" << offset << " Hz";
                if (options.center_frequency_hz) std::cout << " freq=" << center + offset << " Hz";
                std::cout << " level=" << dbfs << " dBFS/bin\n";
            }

            if (!options.spectrum_csv.empty()) {
                std::ofstream csv(options.spectrum_csv, std::ios::trunc);
                if (!csv) {
                    std::cerr << "Cannot write spectrum CSV: " << options.spectrum_csv << '\n';
                    return 4;
                }
                csv << "frequency_offset_hz,frequency_hz,mean_power_dbfs_per_bin\n";
                const double center = options.center_frequency_hz.value_or(0.0);
                for (std::size_t shifted = 0; shifted < fft_size; ++shifted) {
                    const std::size_t k = (shifted + fft_size / 2U) % fft_size;
                    const double signed_bin = static_cast<double>(shifted) - static_cast<double>(fft_size / 2U);
                    const double offset = signed_bin * *options.sample_rate_hz / static_cast<double>(fft_size);
                    const double dbfs = 10.0 * std::log10(std::max(power_sum[k] / static_cast<double>(fft_windows), 1e-30));
                    csv << std::setprecision(10) << offset << ',';
                    if (options.center_frequency_hz) csv << center + offset;
                    csv << ',' << dbfs << '\n';
                }
                std::cout << "  Spectrum CSV:          " << options.spectrum_csv << '\n';
            }
        }
    } else {
        std::cout << "  Spectrum:              not computed (pass --rate to enable FFT analysis)\n";
    }
    std::cout << "Note: dBFS/bin is relative digital level, not calibrated field strength or power at the antenna.\n";

    if (summary_out) *summary_out = summary;
    return 0;
}

} // namespace rfsec
