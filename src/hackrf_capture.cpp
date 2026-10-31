#include "rfsec/hackrf_capture.hpp"

#include <hackrf.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <csignal>
#include <cstdint>
#include <deque>
#include <fstream>
#include <iostream>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace rfsec {
namespace {

volatile std::sig_atomic_t g_stop_requested = 0;
void handle_signal(int) { g_stop_requested = 1; }

struct CaptureContext {
    std::mutex mutex;
    std::condition_variable cv;
    std::deque<std::vector<std::uint8_t>> chunks;
    std::size_t queued_bytes = 0;
    std::size_t dropped_bytes = 0;
    bool finished = false;
    bool writer_failed = false;
    static constexpr std::size_t kMaxQueuedBytes = 64U * 1024U * 1024U;
};

int rx_callback(hackrf_transfer* transfer) {
    if (transfer == nullptr || transfer->rx_ctx == nullptr) return 1;
    auto* ctx = static_cast<CaptureContext*>(transfer->rx_ctx);
    if (g_stop_requested != 0) return 1;
    if (transfer->valid_length <= 0 || transfer->buffer == nullptr) return 0;

    const auto size = static_cast<std::size_t>(transfer->valid_length);
    {
        std::lock_guard<std::mutex> lock(ctx->mutex);
        if (ctx->queued_bytes + size <= CaptureContext::kMaxQueuedBytes) {
            ctx->chunks.emplace_back(transfer->buffer, transfer->buffer + size);
            ctx->queued_bytes += size;
            ctx->cv.notify_one();
        } else {
            ctx->dropped_bytes += size;
        }
    }
    return 0;
}

bool write_metadata(const CaptureOptions& options, std::uint64_t bytes,
                    std::size_t dropped_bytes, const std::filesystem::path& path) {
    std::ofstream json(path, std::ios::trunc);
    if (!json) return false;
    json << "{\n"
         << "  \"format\": \"HackRF raw interleaved signed int8 I/Q\",\n"
         << "  \"frequency_hz\": " << options.frequency_hz << ",\n"
         << "  \"sample_rate_sps\": " << options.sample_rate_sps << ",\n"
         << "  \"duration_limit_seconds\": " << options.duration_seconds << ",\n"
         << "  \"lna_gain_db\": " << options.lna_gain_db << ",\n"
         << "  \"vga_gain_db\": " << options.vga_gain_db << ",\n"
         << "  \"bytes_written\": " << bytes << ",\n"
         << "  \"queue_dropped_bytes\": " << dropped_bytes << ",\n"
         << "  \"transmit_enabled\": false\n"
         << "}\n";
    return static_cast<bool>(json);
}

} // namespace

int capture_hackrf_rx(const CaptureOptions& options) {
    if (options.frequency_hz < 1'000'000ULL || options.frequency_hz > 6'000'000'000ULL) {
        std::cerr << "Frequency must be within the documented 1 MHz-6 GHz range.\n";
        return 2;
    }
    if (options.sample_rate_sps < 2'000'000U || options.sample_rate_sps > 20'000'000U) {
        std::cerr << "Sample rate must be between 2 and 20 MS/s.\n";
        return 2;
    }
    if (options.duration_seconds == 0 || options.duration_seconds > 3600) {
        std::cerr << "Duration must be 1..3600 seconds.\n";
        return 2;
    }
    if (options.lna_gain_db > 40 || (options.lna_gain_db % 8U) != 0U) {
        std::cerr << "LNA gain must be 0..40 dB in 8 dB steps.\n";
        return 2;
    }
    if (options.vga_gain_db > 62 || (options.vga_gain_db % 2U) != 0U) {
        std::cerr << "VGA gain must be 0..62 dB in 2 dB steps.\n";
        return 2;
    }
    if (options.output_file.empty()) {
        std::cerr << "Output path is required.\n";
        return 2;
    }

    std::ofstream output(options.output_file, std::ios::binary | std::ios::trunc);
    if (!output) {
        std::cerr << "Cannot create output file: " << options.output_file << '\n';
        return 2;
    }

    int result = hackrf_init();
    if (result != HACKRF_SUCCESS) {
        std::cerr << "hackrf_init: " << hackrf_error_name(static_cast<hackrf_error>(result))
                  << " (" << result << ")\n";
        return 3;
    }

    hackrf_device* device = nullptr;
    result = hackrf_open(&device);
    if (result != HACKRF_SUCCESS || device == nullptr) {
        std::cerr << "hackrf_open: " << hackrf_error_name(static_cast<hackrf_error>(result))
                  << " (" << result << ")\n";
        hackrf_exit();
        return 3;
    }

    bool device_closed = false;
    const auto cleanup = [&]() {
        if (!device_closed) {
            (void)hackrf_close(device);
            device_closed = true;
        }
        (void)hackrf_exit();
    };
    const auto check = [&](int code, const char* operation) {
        if (code == HACKRF_SUCCESS) return true;
        std::cerr << operation << ": " << hackrf_error_name(static_cast<hackrf_error>(code))
                  << " (" << code << ")\n";
        return false;
    };

    if (!check(hackrf_set_freq(device, options.frequency_hz), "hackrf_set_freq") ||
        !check(hackrf_set_sample_rate(device, static_cast<double>(options.sample_rate_sps)), "hackrf_set_sample_rate") ||
        !check(hackrf_set_lna_gain(device, static_cast<std::uint32_t>(options.lna_gain_db)), "hackrf_set_lna_gain") ||
        !check(hackrf_set_vga_gain(device, static_cast<std::uint32_t>(options.vga_gain_db)), "hackrf_set_vga_gain")) {
        cleanup();
        return 3;
    }

    CaptureContext context;
    std::thread writer([&]() {
        for (;;) {
            std::vector<std::uint8_t> chunk;
            {
                std::unique_lock<std::mutex> lock(context.mutex);
                context.cv.wait(lock, [&]() { return !context.chunks.empty() || context.finished; });
                if (context.chunks.empty() && context.finished) break;
                chunk = std::move(context.chunks.front());
                context.chunks.pop_front();
                context.queued_bytes -= chunk.size();
            }
            output.write(reinterpret_cast<const char*>(chunk.data()),
                         static_cast<std::streamsize>(chunk.size()));
            if (!output) {
                std::lock_guard<std::mutex> lock(context.mutex);
                context.writer_failed = true;
                g_stop_requested = 1;
            }
        }
    });

    g_stop_requested = 0;
    const auto old_int = std::signal(SIGINT, handle_signal);
    const auto old_term = std::signal(SIGTERM, handle_signal);
    result = hackrf_start_rx(device, rx_callback, &context);
    if (result != HACKRF_SUCCESS) {
        std::cerr << "hackrf_start_rx: " << hackrf_error_name(static_cast<hackrf_error>(result))
                  << " (" << result << ")\n";
        {
            std::lock_guard<std::mutex> lock(context.mutex);
            context.finished = true;
        }
        context.cv.notify_all();
        writer.join();
        std::signal(SIGINT, old_int);
        std::signal(SIGTERM, old_term);
        cleanup();
        return 3;
    }

    std::cout << "HackRF RX capture active\n"
              << "  Center frequency: " << options.frequency_hz << " Hz\n"
              << "  Sample rate:      " << options.sample_rate_sps << " samples/s\n"
              << "  LNA / VGA gain:   " << options.lna_gain_db << " / " << options.vga_gain_db << " dB\n"
              << "  Duration limit:   " << options.duration_seconds << " s\n"
              << "  Output:           " << options.output_file << "\n"
              << "  Mode:             RX only; no RF transmission\n"
              << "Press Ctrl+C to stop early.\n";

    const auto deadline = std::chrono::steady_clock::now() +
                          std::chrono::seconds(options.duration_seconds);
    while (g_stop_requested == 0 && std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(40));
    }
    g_stop_requested = 1;
    const int stop_result = hackrf_stop_rx(device);

    {
        std::lock_guard<std::mutex> lock(context.mutex);
        context.finished = true;
    }
    context.cv.notify_all();
    writer.join();
    output.flush();
    const auto position = output.tellp();
    const std::uint64_t bytes_written = position >= 0 ? static_cast<std::uint64_t>(position) : 0;

    std::size_t dropped = 0;
    bool writer_failed = false;
    {
        std::lock_guard<std::mutex> lock(context.mutex);
        dropped = context.dropped_bytes;
        writer_failed = context.writer_failed;
    }
    std::signal(SIGINT, old_int);
    std::signal(SIGTERM, old_term);
    cleanup();

    auto metadata_path = options.output_file;
    metadata_path += ".json";
    const bool metadata_ok = write_metadata(options, bytes_written, dropped, metadata_path);

    std::cout << "Capture finished\n"
              << "  Bytes written:       " << bytes_written << '\n'
              << "  Queue-dropped bytes: " << dropped << '\n'
              << "  Metadata:            " << (metadata_ok ? metadata_path.string() : "write failed") << '\n';

    if (stop_result != HACKRF_SUCCESS) {
        std::cerr << "hackrf_stop_rx: " << hackrf_error_name(static_cast<hackrf_error>(stop_result))
                  << " (" << stop_result << ")\n";
    }
    if (!output || writer_failed || !metadata_ok) return 4;
    if (dropped != 0) {
        std::cerr << "Warning: capture queue overflow dropped samples; this file has gaps.\n";
        return 5;
    }
    return 0;
}

int capture_capability_status() {
    std::cout << "HackRF support: enabled (libhackrf linked)\n";
    return 0;
}

} // namespace rfsec
