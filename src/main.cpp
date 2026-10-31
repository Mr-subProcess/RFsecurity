#include "rfsec/android_device.hpp"
#include "rfsec/cellular_anomaly.hpp"
#include "rfsec/comms_audit.hpp"
#include "rfsec/interference_monitor.hpp"
#include "rfsec/frame_parser.hpp"
#include "rfsec/hackrf_capture.hpp"
#include "rfsec/iq_analyzer.hpp"
#include "rfsec/mutator.hpp"
#include "rfsec/telecom_config_audit.hpp"

#include <charconv>
#include <cmath>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <random>
#include <set>
#include <string>
#include <string_view>
#include <vector>

namespace {

using Args = std::map<std::string, std::string>;

void usage() {
    std::cout << R"(RFSEC 0.6.0 — C++20 RF + Cellular Assurance Toolkit

Commands:
  rfsec status
  rfsec capture --freq HZ --rate SPS --seconds N --out FILE.iq8 [--lna DB] [--vga DB]
  rfsec analyze --in FILE.iq8 [--rate SPS] [--center HZ] [--fft-size N] [--csv spectrum.csv]
  rfsec mutate --seed FRAME.bin --out DIR [--count N] [--kind KIND]
               [--rng-seed N] [--max-size BYTES]
  rfsec validate --in FRAME.bin
  rfsec device list
  rfsec device inspect --serial ADB_SERIAL
  rfsec device audit --serial ADB_SERIAL [--out audit.json]
  rfsec device call-ui --serial ADB_SERIAL --number +905321234567
  rfsec device sms-ui --serial ADB_SERIAL --number +905321234567
  rfsec telecom menu
  rfsec telecom audit --serial ADB_SERIAL [--out audit.json]
  rfsec telecom config-audit --file RAN_OR_CORE_CONFIG [--out config-audit.json]
  rfsec telecom cell-audit --in observations.csv [--out findings.csv] [--allow-plmn MCC-MNC,...]
  rfsec telecom rf-audit --in FILE.iq8 --rate SPS [--center HZ] [--fft-size N] [--out findings.csv]
  rfsec telecom comms-audit --in gateway-events.csv [--out findings.csv]
         [--window-sec N] [--max-events N] [--max-fanout N]
  rfsec help

Mutation kinds:
  all, bitflip, truncate, extend, duplicate, zero, insert, erase, boundary, shuffle, length

Examples:
  rfsec capture --freq 433920000 --rate 2000000 --seconds 8 --out lab.iq8
  rfsec analyze --in lab.iq8 --rate 2000000 --center 433920000 --fft-size 4096 --csv lab-spectrum.csv
  rfsec mutate --seed examples/seed_frame.bin --out corpus --count 500 --kind all --rng-seed 42
  rfsec validate --in examples/seed_frame.bin

Notes:
  * Hardware support is optional at build time. Without libhackrf, offline commands still work.
  * IQ files are raw interleaved signed 8-bit I,Q. Capture also creates FILE.iq8.json metadata.
  * HackRF support is receive-only. Telecom monitors analyze exported metadata and IQ files.
  * RFSEC has no jammer, rogue-cell, spoofing, interception, or OTA injection implementation.
  * Android audit is read-only and reports device security posture without subscriber identifiers.
  * Android call-ui and sms-ui open the selected phone's native UI; they do not send automatically.
  * Cellular testing should use devices/SIMs and a private network you own or
    are explicitly authorized to assess.
  * Mutation output is for offline testing of parsers you own or are authorized to assess.
)";
}

bool parse_args(int argc, char** argv, int start, Args& out) {
    for (int i = start; i < argc; ++i) {
        const std::string key = argv[i];
        if (key.size() < 3 || key.rfind("--", 0) != 0 || i + 1 >= argc) {
            std::cerr << "Invalid or incomplete option: " << key << '\n';
            return false;
        }
        const std::string value = argv[++i];
        if (value.rfind("--", 0) == 0) {
            std::cerr << "Missing value for option: " << key << '\n';
            return false;
        }
        out[key] = value;
    }
    return true;
}

std::string get(const Args& args, const std::string& key, const std::string& fallback = {}) {
    const auto it = args.find(key);
    return it == args.end() ? fallback : it->second;
}

bool parse_u64(const std::string& text, std::uint64_t& value) {
    if (text.empty() || text.front() == '-') return false;
    std::uint64_t parsed = 0;
    const auto result = std::from_chars(text.data(), text.data() + text.size(), parsed);
    if (result.ec != std::errc{} || result.ptr != text.data() + text.size()) return false;
    value = parsed;
    return true;
}

bool parse_double(const std::string& text, double& value) {
    try {
        std::size_t used = 0;
        const double parsed = std::stod(text, &used);
        if (used != text.size() || !std::isfinite(parsed)) return false;
        value = parsed;
        return true;
    } catch (...) {
        return false;
    }
}

bool read_file_bounded(const std::filesystem::path& path, std::vector<std::uint8_t>& bytes,
                       std::size_t max_size) {
    std::error_code ec;
    const auto size = std::filesystem::file_size(path, ec);
    if (ec || size > max_size) return false;
    std::ifstream in(path, std::ios::binary);
    if (!in) return false;
    bytes.assign(std::istreambuf_iterator<char>(in), {});
    return bytes.size() == size;
}


std::set<std::string> parse_plmn_allowlist(const std::string& value) {
    std::set<std::string> out;
    std::size_t begin = 0;
    while (begin < value.size()) {
        const auto end = value.find(',', begin);
        const auto item = value.substr(begin, end == std::string::npos ? std::string::npos : end - begin);
        if (!item.empty()) out.insert(item);
        if (end == std::string::npos) break;
        begin = end + 1U;
    }
    return out;
}

int command_telecom(int argc, char** argv) {
    if (argc < 3) return 2;
    const std::string sub = argv[2];
    if (sub == "menu" && argc == 3) return rfsec::android::run_telecom_menu();
    Args a;
    if (!parse_args(argc, argv, 3, a)) return 2;
    if (sub == "audit") {
        const auto serial = get(a, "--serial");
        if (serial.empty()) { std::cerr << "telecom audit requires --serial ADB_SERIAL\\n"; return 2; }
        return rfsec::android::audit_device(serial, get(a, "--out"));
    }
    if (sub == "config-audit") {
        const auto file = get(a, "--file");
        if (file.empty()) { std::cerr << "telecom config-audit requires --file CONFIG\\n"; return 2; }
        return rfsec::telecom::audit_config_file(file, get(a, "--out"));
    }
    if (sub == "cell-audit") {
        const auto in = get(a, "--in");
        if (in.empty()) { std::cerr << "cell-audit requires --in observations.csv\\n"; return 2; }
        const auto allow = parse_plmn_allowlist(get(a, "--allow-plmn"));
        return rfsec::telecom::audit_cell_observations(in, get(a, "--out"), allow);
    }
    if (sub == "rf-audit") {
        const auto in = get(a, "--in");
        double rate = 0.0, center = 0.0;
        std::uint64_t fft = 2048;
        if (in.empty() || !parse_double(get(a, "--rate"), rate) || rate <= 0.0 ||
            (!get(a, "--center").empty() && !parse_double(get(a, "--center"), center)) ||
            !parse_u64(get(a, "--fft-size", "2048"), fft) || fft > UINT32_MAX) {
            std::cerr << "rf-audit requires --in FILE.iq8 --rate SPS [--center HZ] [--fft-size N]\\n"; return 2;
        }
        rfsec::telecom::InterferenceOptions options;
        options.sample_rate_hz = rate; options.center_frequency_hz = center;
        options.fft_size = static_cast<std::uint32_t>(fft);
        return rfsec::telecom::audit_iq_interference(in, options, get(a, "--out"));
    }
    if (sub == "comms-audit") {
        const auto in = get(a, "--in");
        if (in.empty()) { std::cerr << "comms-audit requires --in gateway-events.csv\\n"; return 2; }
        rfsec::telecom::CommsAuditOptions options;
        std::uint64_t n = 0;
        if (!parse_u64(get(a, "--window-sec", "60"), n) || n > UINT32_MAX) return 2;
        options.window_seconds = static_cast<std::uint32_t>(n);
        if (!parse_u64(get(a, "--max-events", "20"), n) || n > UINT32_MAX) return 2;
        options.max_events_per_actor = static_cast<std::uint32_t>(n);
        if (!parse_u64(get(a, "--max-fanout", "10"), n) || n > UINT32_MAX) return 2;
        options.max_unique_peers_per_actor = static_cast<std::uint32_t>(n);
        return rfsec::telecom::audit_comms_gateway_log(in, get(a, "--out"), options);
    }
    std::cerr << "Unknown telecom subcommand: " << sub << '\n';
    return 2;
}

int command_validate(const Args& args) {
    const auto input = get(args, "--in");
    if (input.empty()) {
        std::cerr << "validate requires --in FILE\n";
        return 2;
    }
    std::vector<std::uint8_t> bytes;
    if (!read_file_bounded(input, bytes, 2U * 1024U * 1024U)) {
        std::cerr << "Cannot read input or file exceeds 2 MiB.\n";
        return 2;
    }
    const auto result = rfsec::frame::parse(bytes);
    std::cout << "Example frame parser: " << rfsec::frame::to_string(result) << '\n'
              << "  Input bytes: " << bytes.size() << '\n'
              << "  Status:      " << (result == rfsec::frame::ParseResult::Ok ? "ACCEPT" : "REJECT") << '\n';
    return result == rfsec::frame::ParseResult::Ok ? 0 : 1;
}

int command_capture(const Args& args) {
    rfsec::CaptureOptions options;
    std::uint64_t value = 0;
    const auto frequency = get(args, "--freq");
    const auto rate = get(args, "--rate", "2000000");
    const auto seconds = get(args, "--seconds", "10");
    const auto lna = get(args, "--lna", "16");
    const auto vga = get(args, "--vga", "20");
    options.output_file = get(args, "--out");
    if (frequency.empty() || options.output_file.empty() ||
        !parse_u64(frequency, options.frequency_hz) ||
        !parse_u64(rate, value) || value > UINT32_MAX) {
        std::cerr << "capture requires valid --freq, --rate and --out values.\n";
        return 2;
    }
    options.sample_rate_sps = static_cast<std::uint32_t>(value);
    if (!parse_u64(seconds, value) || value > UINT32_MAX) return 2;
    options.duration_seconds = static_cast<std::uint32_t>(value);
    if (!parse_u64(lna, value) || value > UINT32_MAX) return 2;
    options.lna_gain_db = static_cast<std::uint32_t>(value);
    if (!parse_u64(vga, value) || value > UINT32_MAX) return 2;
    options.vga_gain_db = static_cast<std::uint32_t>(value);
    return rfsec::capture_hackrf_rx(options);
}

int command_analyze(const Args& args) {
    const auto input = get(args, "--in");
    if (input.empty()) {
        std::cerr << "analyze requires --in FILE.iq8\n";
        return 2;
    }
    rfsec::IqAnalysisOptions options;
    const auto rate = get(args, "--rate");
    const auto center = get(args, "--center");
    const auto fft_size = get(args, "--fft-size", "4096");
    std::uint64_t integer = 0;
    double real = 0.0;
    if (!rate.empty()) {
        if (!parse_double(rate, real) || real <= 0.0) return 2;
        options.sample_rate_hz = real;
    }
    if (!center.empty()) {
        if (!parse_double(center, real) || real < 0.0) return 2;
        options.center_frequency_hz = real;
    }
    if (!parse_u64(fft_size, integer) || integer > UINT32_MAX) return 2;
    options.fft_size = static_cast<std::uint32_t>(integer);
    options.spectrum_csv = get(args, "--csv");
    if (!options.spectrum_csv.empty() && !options.sample_rate_hz) {
        std::cerr << "--csv requires --rate so frequency bins can be labelled.\n";
        return 2;
    }
    return rfsec::analyze_iq_file(input, options);
}

int command_mutate(const Args& args) {
    const auto seed_file = get(args, "--seed");
    const auto output = get(args, "--out");
    if (seed_file.empty() || output.empty()) {
        std::cerr << "mutate requires --seed FILE and --out DIR\n";
        return 2;
    }
    std::uint64_t count = 128;
    std::uint64_t rng_seed = 0;
    std::uint64_t max_size = 4096;
    if (!parse_u64(get(args, "--count", "128"), count) ||
        !parse_u64(get(args, "--rng-seed", "0"), rng_seed) ||
        !parse_u64(get(args, "--max-size", "4096"), max_size) || max_size > SIZE_MAX) {
        std::cerr << "Invalid numeric mutation option.\n";
        return 2;
    }
    if (!args.contains("--rng-seed")) {
        std::random_device rd;
        rng_seed = (static_cast<std::uint64_t>(rd()) << 32U) ^ rd();
    }
    rfsec::MutationKind kind{};
    if (!rfsec::parse_mutation_kind(get(args, "--kind", "all"), kind)) {
        std::cerr << "Unknown mutation kind.\n";
        return 2;
    }
    return rfsec::generate_corpus(seed_file, output, count, kind, rng_seed,
                                  static_cast<std::size_t>(max_size));
}

} // namespace

int main(int argc, char** argv) {
    if (argc < 2) {
        usage();
        return 1;
    }
    const std::string command = argv[1];
    if (command == "help" || command == "--help" || command == "-h") {
        usage();
        return 0;
    }
    if (command == "version" || command == "--version") {
        std::cout << "RFSEC 0.6.0 (C++20)\n";
        return 0;
    }
    if (command == "status") return rfsec::capture_capability_status();

    if (command == "telecom") return command_telecom(argc, argv);

    if (command == "device") {
        if (argc < 3) {
            std::cerr << "Usage: rfsec device {list|inspect|audit|call-ui|sms-ui} [options]\n";
            return 2;
        }
        const std::string subcommand = argv[2];
        if (subcommand == "list" && argc == 3) return rfsec::android::list_devices();
        Args device_args;
        if (!parse_args(argc, argv, 3, device_args)) return 2;
        const auto serial = get(device_args, "--serial");
        if (serial.empty()) {
            std::cerr << "This device command requires --serial ADB_SERIAL.\n";
            return 2;
        }
        if (subcommand == "inspect") return rfsec::android::inspect_device(serial);
        if (subcommand == "audit") return rfsec::android::audit_device(serial, get(device_args, "--out"));
        const auto number = get(device_args, "--number");
        if (subcommand == "call-ui") return rfsec::android::open_dialer(serial, number);
        if (subcommand == "sms-ui") return rfsec::android::open_sms_composer(serial, number);
        std::cerr << "Unknown device subcommand: " << subcommand << '\n';
        return 2;
    }

    Args args;
    if (!parse_args(argc, argv, 2, args)) return 2;
    if (command == "capture") return command_capture(args);
    if (command == "analyze") return command_analyze(args);
    if (command == "mutate") return command_mutate(args);
    if (command == "validate") return command_validate(args);

    std::cerr << "Unknown command: " << command << '\n';
    usage();
    return 2;
}
