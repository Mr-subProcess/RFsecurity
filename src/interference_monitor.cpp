#include "rfsec/interference_monitor.hpp"

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
#include <vector>

namespace rfsec::telecom {
namespace {
using Complex = std::complex<double>;

bool power_of_two(std::size_t n) { return n >= 256U && n <= 65536U && (n & (n - 1U)) == 0U; }

void fft(std::vector<Complex>& a) {
    const std::size_t n = a.size();
    for (std::size_t i = 1, j = 0; i < n; ++i) {
        std::size_t bit = n >> 1U;
        for (; (j & bit) != 0U; bit >>= 1U) j ^= bit;
        j ^= bit;
        if (i < j) std::swap(a[i], a[j]);
    }
    for (std::size_t len = 2; len <= n; len <<= 1U) {
        const double angle = -2.0 * std::numbers::pi / static_cast<double>(len);
        const Complex wlen(std::cos(angle), std::sin(angle));
        for (std::size_t i = 0; i < n; i += len) {
            Complex w(1.0, 0.0);
            for (std::size_t j = 0; j < len / 2U; ++j) {
                const Complex u = a[i + j];
                const Complex v = a[i + j + len / 2U] * w;
                a[i + j] = u + v;
                a[i + j + len / 2U] = u - v;
                w *= wlen;
            }
        }
        if (len == n) break;
    }
}

double median(std::vector<double> values) {
    if (values.empty()) return 0.0;
    const auto mid = values.begin() + static_cast<std::ptrdiff_t>(values.size() / 2U);
    std::nth_element(values.begin(), mid, values.end());
    if (values.size() % 2U) return *mid;
    const auto lower = std::max_element(values.begin(), mid);
    return (*lower + *mid) / 2.0;
}

} // namespace

int audit_iq_interference(const std::filesystem::path& input_iq8,
                          const InterferenceOptions& options,
                          const std::filesystem::path& output_csv,
                          InterferenceReport* report_out) {
    if (!power_of_two(options.fft_size) || !std::isfinite(options.sample_rate_hz) ||
        options.sample_rate_hz <= 0.0 || !std::isfinite(options.center_frequency_hz) ||
        options.center_frequency_hz < 0.0 || options.flatness_warning_threshold <= 0.0 ||
        options.flatness_warning_threshold >= 1.0 || options.clipping_warning_ratio < 0.0 ||
        options.clipping_warning_ratio > 1.0) {
        std::cerr << "Invalid passive interference analysis options.\n"; return 2;
    }
    std::error_code ec;
    const auto bytes = std::filesystem::file_size(input_iq8, ec);
    if (ec || bytes < 2U || bytes % 2U != 0U) {
        std::cerr << "IQ8 input is missing, empty or has incomplete I/Q pairs.\n"; return 2;
    }
    std::ifstream input(input_iq8, std::ios::binary);
    if (!input) { std::cerr << "Cannot open IQ8 input.\n"; return 2; }

    const std::size_t n = options.fft_size;
    std::vector<std::uint8_t> raw(n * 2U);
    std::vector<Complex> bins(n);
    std::vector<double> window(n);
    for (std::size_t i = 0; i < n; ++i) {
        window[i] = 0.5 - 0.5 * std::cos(2.0 * std::numbers::pi * static_cast<double>(i) / static_cast<double>(n));
    }

    InterferenceReport report;
    std::uint64_t total_clipped = 0;
    std::uint64_t total_components = 0;
    while (true) {
        input.read(reinterpret_cast<char*>(raw.data()), static_cast<std::streamsize>(raw.size()));
        const auto got = static_cast<std::size_t>(input.gcount());
        if (got == 0U) break;
        if (got % 2U != 0U) { std::cerr << "Trailing partial I/Q pair in IQ8 file.\n"; return 2; }
        const std::size_t samples = got / 2U;
        report.samples += samples;
        std::uint64_t block_clipped = 0;
        for (std::size_t i = 0; i < samples; ++i) {
            const auto iv = std::bit_cast<std::int8_t>(raw[2U * i]);
            const auto qv = std::bit_cast<std::int8_t>(raw[2U * i + 1U]);
            total_components += 2U;
            if (std::abs(static_cast<int>(iv)) >= 127) { ++total_clipped; ++block_clipped; }
            if (std::abs(static_cast<int>(qv)) >= 127) { ++total_clipped; ++block_clipped; }
        }
        if (samples != n) continue; // do not treat a final partial window as FFT input

        long double sum_power = 0.0L;
        for (std::size_t i = 0; i < n; ++i) {
            const auto iv = static_cast<double>(std::bit_cast<std::int8_t>(raw[2U * i]));
            const auto qv = static_cast<double>(std::bit_cast<std::int8_t>(raw[2U * i + 1U]));
            bins[i] = Complex(iv * window[i], qv * window[i]);
            sum_power += iv * iv + qv * qv;
        }
        fft(bins);
        std::vector<double> powers(n);
        double peak = 0.0;
        double log_sum = 0.0;
        double arithmetic_sum = 0.0;
        for (std::size_t i = 0; i < n; ++i) {
            powers[i] = std::norm(bins[i]);
            peak = std::max(peak, powers[i]);
            const double safe = std::max(powers[i], 1e-18);
            log_sum += std::log(safe);
            arithmetic_sum += safe;
        }
        const double median_power = std::max(median(powers), 1e-18);
        const double flatness = std::exp(log_sum / static_cast<double>(n)) /
                                std::max(arithmetic_sum / static_cast<double>(n), 1e-18);
        const double threshold = median_power * 4.0; // +6 dB relative to median bin
        const auto occupied = std::count_if(powers.begin(), powers.end(), [&](double p) { return p > threshold; });
        const double rms_component = std::sqrt(static_cast<double>(sum_power / (2.0L * n)));
        const double rms_dbfs = rms_component > 0.0 ? 20.0 * std::log10(rms_component / 127.0)
                                                    : -std::numeric_limits<double>::infinity();
        const double window_clip = static_cast<double>(block_clipped) / static_cast<double>(2U * n);
        const double p2m = 10.0 * std::log10(std::max(peak / median_power, 1e-18));

        InterferenceWindow w;
        w.window_index = report.fft_windows++;
        w.rms_dbfs = rms_dbfs;
        w.spectral_flatness = flatness;
        w.peak_to_median_db = p2m;
        w.occupied_fraction = static_cast<double>(occupied) / static_cast<double>(n);
        w.clipping_fraction = window_clip;
        if (window_clip >= options.clipping_warning_ratio && window_clip > 0.0) {
            w.assessment = "CAPTURE_OVERLOAD_OR_CLIPPING";
        } else if (flatness >= options.flatness_warning_threshold && rms_dbfs > -35.0) {
            w.assessment = "BROADBAND_NOISE_LIKE_PATTERN";
        } else if (p2m > 18.0) {
            w.assessment = "NARROWBAND_DOMINANT_PATTERN";
        } else {
            w.assessment = "NO_RULE_TRIGGERED";
        }
        report.windows.push_back(std::move(w));
    }

    std::ostream* out = &std::cout;
    std::ofstream csv;
    if (!output_csv.empty()) {
        csv.open(output_csv, std::ios::trunc);
        if (!csv) { std::cerr << "Cannot create interference report CSV.\n"; return 2; }
        out = &csv;
    }
    *out << "window,rms_dbfs,spectral_flatness,peak_to_median_db,occupied_fraction,clipping_fraction,assessment\n";
    for (const auto& w : report.windows) {
        *out << w.window_index << ',' << std::setprecision(9) << w.rms_dbfs << ','
             << w.spectral_flatness << ',' << w.peak_to_median_db << ',' << w.occupied_fraction << ','
             << w.clipping_fraction << ',' << w.assessment << '\n';
    }
    const double global_clip = total_components ? static_cast<double>(total_clipped) / static_cast<double>(total_components) : 0.0;
    std::cout << "Passive RF interference indicators\n"
              << "  Input samples:       " << report.samples << '\n'
              << "  FFT windows:         " << report.fft_windows << '\n'
              << "  Clipped components:  " << global_clip * 100.0 << "%\n"
              << "  Sample rate:         " << options.sample_rate_hz << " S/s\n"
              << "  Center frequency:    " << options.center_frequency_hz << " Hz\n";
    std::size_t noise_like = 0, overloaded = 0;
    for (const auto& w : report.windows) {
        if (w.assessment == "BROADBAND_NOISE_LIKE_PATTERN") ++noise_like;
        if (w.assessment == "CAPTURE_OVERLOAD_OR_CLIPPING") ++overloaded;
    }
    std::cout << "  Broadband-like:      " << noise_like << " windows\n"
              << "  Overload/clipping:   " << overloaded << " windows\n"
              << "Interpretation: these are signal-quality indicators, not proof of jamming or malicious activity.\n";
    if (!output_csv.empty()) std::cout << "  Report:              " << output_csv << '\n';
    if (report_out) *report_out = std::move(report);
    return 0;
}

int InterferenceMonitor::analyze(const std::filesystem::path& input_iq8,
                                 const std::filesystem::path& output_csv,
                                 InterferenceReport* report_out) const {
    return audit_iq_interference(input_iq8, options_, output_csv, report_out);
}

} // namespace rfsec::telecom
