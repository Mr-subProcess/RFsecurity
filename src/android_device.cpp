#include "rfsec/android_device.hpp"
#include "rfsec/telecom_config_audit.hpp"
#include "rfsec/cellular_anomaly.hpp"
#include "rfsec/interference_monitor.hpp"
#include "rfsec/comms_audit.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <cerrno>
#include <cstring>
#include <fstream>
#include <iostream>
#include <sstream>
#include <set>
#include <chrono>
#include <ctime>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#if defined(__unix__) || defined(__APPLE__)
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#else
#error "RFSEC Android ADB controller currently requires Linux or macOS (POSIX process APIs)."
#endif

namespace rfsec::android {
namespace {

struct ProcessResult {
    int exit_code = 127;
    std::string output;
};

ProcessResult run_process(const std::vector<std::string>& arguments) {
    ProcessResult result;
    if (arguments.empty()) {
        result.output = "No process arguments supplied.\n";
        return result;
    }

    int pipe_fd[2]{};
    if (::pipe(pipe_fd) != 0) {
        result.output = std::string("pipe() failed: ") + std::strerror(errno) + "\n";
        return result;
    }

    const pid_t child = ::fork();
    if (child < 0) {
        result.output = std::string("fork() failed: ") + std::strerror(errno) + "\n";
        ::close(pipe_fd[0]);
        ::close(pipe_fd[1]);
        return result;
    }

    if (child == 0) {
        ::close(pipe_fd[0]);
        (void)::dup2(pipe_fd[1], STDOUT_FILENO);
        (void)::dup2(pipe_fd[1], STDERR_FILENO);
        ::close(pipe_fd[1]);

        std::vector<char*> argv;
        argv.reserve(arguments.size() + 1U);
        for (const auto& argument : arguments) {
            argv.push_back(const_cast<char*>(argument.c_str()));
        }
        argv.push_back(nullptr);
        ::execvp(argv[0], argv.data());
        const std::string error = std::string("execvp failed: ") + std::strerror(errno) + "\n";
        (void)::write(STDERR_FILENO, error.data(), error.size());
        _exit(127);
    }

    ::close(pipe_fd[1]);
    std::array<char, 4096> buffer{};
    for (;;) {
        const ssize_t count = ::read(pipe_fd[0], buffer.data(), buffer.size());
        if (count > 0) {
            // All commands used here have bounded, human-readable output.
            if (result.output.size() < 1024U * 1024U) {
                const auto remaining = 1024U * 1024U - result.output.size();
                result.output.append(buffer.data(), std::min<std::size_t>(
                    static_cast<std::size_t>(count), remaining));
            }
        } else if (count == 0) {
            break;
        } else if (errno != EINTR) {
            break;
        }
    }
    ::close(pipe_fd[0]);

    int status = 0;
    while (::waitpid(child, &status, 0) < 0) {
        if (errno != EINTR) return result;
    }
    if (WIFEXITED(status)) result.exit_code = WEXITSTATUS(status);
    else if (WIFSIGNALED(status)) result.exit_code = 128 + WTERMSIG(status);
    return result;
}

bool valid_serial(std::string_view serial) noexcept {
    if (serial.empty() || serial.size() > 128U) return false;
    return std::all_of(serial.begin(), serial.end(), [](unsigned char c) {
        return std::isalnum(c) != 0 || c == '.' || c == '_' || c == ':' || c == '-';
    });
}

bool device_ready(const std::string& serial) {
    if (!valid_serial(serial)) {
        std::cerr << "Invalid ADB serial. Allowed characters: letters, digits, '.', '_', ':' and '-'.\n";
        return false;
    }
    const auto result = run_process({"adb", "-s", serial, "get-state"});
    if (result.exit_code != 0 || result.output.find("device") == std::string::npos) {
        std::cerr << "ADB device is not ready. Run `rfsec device list` and check USB debugging authorization.\n";
        if (!result.output.empty()) std::cerr << result.output;
        return false;
    }
    return true;
}

std::string get_property(const std::string& serial, const std::string& property) {
    const auto result = run_process({"adb", "-s", serial, "shell", "getprop", property});
    if (result.exit_code != 0) return "(unavailable)";
    auto value = result.output;
    while (!value.empty() && (value.back() == '\n' || value.back() == '\r')) value.pop_back();
    return value.empty() ? "(not reported)" : value;
}

std::string get_setting(const std::string& serial, const std::string& name_space,
                        const std::string& key) {
    const auto result = run_process({"adb", "-s", serial, "shell", "settings", "get",
                                     name_space, key});
    if (result.exit_code != 0) return "(unavailable)";
    auto value = result.output;
    while (!value.empty() && (value.back() == '\n' || value.back() == '\r')) value.pop_back();
    return value.empty() ? "(not reported)" : value;
}

std::string json_escape(std::string_view input) {
    std::ostringstream out;
    for (const unsigned char c : input) {
        switch (c) {
            case '\\': out << "\\\\"; break;
            case '"': out << "\\\""; break;
            case '\n': out << "\\n"; break;
            case '\r': out << "\\r"; break;
            case '\t': out << "\\t"; break;
            default:
                if (c < 0x20) out << '?';
                else out << static_cast<char>(c);
        }
    }
    return out.str();
}

bool patch_is_stale(std::string_view patch, int stale_days = 180) {
    if (patch.size() != 10 || patch[4] != '-' || patch[7] != '-') return false;
    int y = 0, m = 0, d = 0;
    try {
        y = std::stoi(std::string(patch.substr(0, 4)));
        m = std::stoi(std::string(patch.substr(5, 2)));
        d = std::stoi(std::string(patch.substr(8, 2)));
    } catch (...) { return false; }
    using namespace std::chrono;
    const year_month_day ymd{year{y}, month{static_cast<unsigned>(m)}, day{static_cast<unsigned>(d)}};
    if (!ymd.ok()) return false;
    const auto patch_day = sys_days{ymd};
    const auto today = floor<days>(system_clock::now());
    return today - patch_day > days{stale_days};
}

struct AuditField { std::string key; std::string value; };
struct AuditFinding { std::string severity; std::string check; std::string detail; };

std::string read_line(const char* prompt) {
    std::cout << prompt << std::flush;
    std::string value;
    std::getline(std::cin, value);
    return value;
}

} // namespace

bool valid_e164_number(std::string_view number) noexcept {
    if (number.size() < 8U || number.size() > 16U || number.front() != '+') return false;
    const auto digits = number.substr(1);
    return std::all_of(digits.begin(), digits.end(), [](unsigned char c) {
        return std::isdigit(c) != 0;
    });
}

int list_devices() {
    const auto result = run_process({"adb", "devices", "-l"});
    std::cout << result.output;
    if (result.exit_code != 0) {
        std::cerr << "Could not execute ADB. Install Android Platform Tools and ensure `adb` is in PATH.\n";
    }
    return result.exit_code;
}

int inspect_device(const std::string& serial) {
    if (!device_ready(serial)) return 2;
    std::cout << "RFSEC — Android device inspection\n"
              << "Serial:             " << serial << '\n'
              << "Model:              " << get_property(serial, "ro.product.model") << '\n'
              << "Manufacturer:       " << get_property(serial, "ro.product.manufacturer") << '\n'
              << "Android version:    " << get_property(serial, "ro.build.version.release") << '\n'
              << "Build fingerprint:  " << get_property(serial, "ro.build.fingerprint") << '\n'
              << "SIM state:          " << get_property(serial, "gsm.sim.state") << '\n'
              << "Carrier label:      " << get_property(serial, "gsm.operator.alpha") << '\n'
              << "Radio technology:   " << get_property(serial, "gsm.network.type") << '\n'
              << "\nPrivacy: IMEI, IMSI, phone numbers, messages and call history are not collected.\n";
    return 0;
}

int audit_device(const std::string& serial, const std::string& output_file) {
    if (!device_ready(serial)) return 2;

    std::vector<AuditField> fields{
        {"serial", serial},
        {"manufacturer", get_property(serial, "ro.product.manufacturer")},
        {"model", get_property(serial, "ro.product.model")},
        {"android_release", get_property(serial, "ro.build.version.release")},
        {"security_patch", get_property(serial, "ro.build.version.security_patch")},
        {"build_fingerprint", get_property(serial, "ro.build.fingerprint")},
        {"encryption_state", get_property(serial, "ro.crypto.state")},
        {"encryption_type", get_property(serial, "ro.crypto.type")},
        {"verified_boot_state", get_property(serial, "ro.boot.verifiedbootstate")},
        {"bootloader_locked", get_property(serial, "ro.boot.flash.locked")},
        {"selinux", [&] { const auto r = run_process({"adb", "-s", serial, "shell", "getenforce"});
                          auto v = r.output; while (!v.empty() && (v.back()=='\n'||v.back()=='\r')) v.pop_back();
                          return r.exit_code == 0 && !v.empty() ? v : std::string("(unavailable)"); }()},
        {"adb_enabled", get_setting(serial, "global", "adb_enabled")},
        {"developer_options", get_setting(serial, "global", "development_settings_enabled")},
        {"airplane_mode", get_setting(serial, "global", "airplane_mode_on")},
        {"sim_state", get_property(serial, "gsm.sim.state")},
        {"carrier_label", get_property(serial, "gsm.operator.alpha")},
        {"radio_technology", get_property(serial, "gsm.network.type")}
    };

    std::vector<AuditFinding> findings;
    const auto value = [&](const std::string& key) -> std::string {
        for (const auto& f : fields) if (f.key == key) return f.value;
        return {};
    };
    const auto selinux = value("selinux");
    if (selinux == "Enforcing") findings.push_back({"PASS", "SELinux", "SELinux is enforcing."});
    else findings.push_back({"WARN", "SELinux", "SELinux is not confirmed enforcing; verify device policy."});

    const auto encryption = value("encryption_state");
    if (encryption == "encrypted") findings.push_back({"PASS", "Storage encryption", "Android reports encrypted storage."});
    else findings.push_back({"WARN", "Storage encryption", "Encryption is absent or could not be verified."});

    const auto verified = value("verified_boot_state");
    if (verified == "green") findings.push_back({"PASS", "Verified Boot", "Verified Boot reports green state."});
    else findings.push_back({"WARN", "Verified Boot", "Verified Boot is not green or the property is unavailable."});

    const auto locked = value("bootloader_locked");
    if (locked == "1") findings.push_back({"PASS", "Bootloader", "Bootloader reports locked."});
    else findings.push_back({"WARN", "Bootloader", "Bootloader is unlocked or lock state is unknown."});

    const auto adb = value("adb_enabled");
    if (adb == "1") findings.push_back({"INFO", "ADB debugging", "ADB debugging is enabled; disable it when no longer needed."});
    else if (adb == "0") findings.push_back({"PASS", "ADB debugging", "ADB debugging is disabled in Android settings."});
    else findings.push_back({"INFO", "ADB debugging", "ADB setting could not be confirmed."});

    const auto patch = value("security_patch");
    if (patch_is_stale(patch)) findings.push_back({"WARN", "Security patch", "Patch date is more than 180 days old; validate vendor support and patch cadence."});
    else if (patch != "(unavailable)" && patch != "(not reported)") findings.push_back({"INFO", "Security patch", "Patch date reported as " + patch + "; confirm against the vendor bulletin."});
    else findings.push_back({"WARN", "Security patch", "Security patch date could not be read."});

    unsigned warn_count = 0;
    for (const auto& finding : findings) if (finding.severity == "WARN") ++warn_count;
    const std::string overall = warn_count == 0 ? "NO_WARNINGS" : "REVIEW_REQUIRED";

    std::cout << "RFSEC Android Security Posture Audit\n"
              << "Device: " << value("manufacturer") << " " << value("model") << " [" << serial << "]\n"
              << "Overall: " << overall << " (" << warn_count << " warning(s))\n\n";
    for (const auto& finding : findings) {
        std::cout << "[" << finding.severity << "] " << finding.check << ": " << finding.detail << '\n';
    }
    std::cout << "\nTelephony context (non-subscriber-identifying): SIM=" << value("sim_state")
              << ", carrier=" << value("carrier_label")
              << ", radio=" << value("radio_technology")
              << ", airplane_mode=" << value("airplane_mode") << '\n';
    std::cout << "Privacy: report excludes IMEI, IMSI, MSISDN, contacts, SMS contents and call history.\n";

    if (!output_file.empty()) {
        std::ofstream out(output_file, std::ios::binary | std::ios::trunc);
        if (!out) {
            std::cerr << "Could not write audit report: " << output_file << '\n';
            return 2;
        }
        out << "{\n  \"tool\": \"RFSEC\",\n  \"version\": \"0.5.0\",\n  \"overall\": \"" << overall << "\",\n  \"fields\": {\n";
        for (std::size_t i = 0; i < fields.size(); ++i) {
            out << "    \"" << json_escape(fields[i].key) << "\": \"" << json_escape(fields[i].value) << "\""
                << (i + 1 == fields.size() ? "\n" : ",\n");
        }
        out << "  },\n  \"findings\": [\n";
        for (std::size_t i = 0; i < findings.size(); ++i) {
            const auto& f = findings[i];
            out << "    {\"severity\":\"" << json_escape(f.severity)
                << "\",\"check\":\"" << json_escape(f.check)
                << "\",\"detail\":\"" << json_escape(f.detail) << "\"}"
                << (i + 1 == findings.size() ? "\n" : ",\n");
        }
        out << "  ]\n}\n";
        if (!out) {
            std::cerr << "Failed while writing audit report.\n";
            return 2;
        }
        std::cout << "\nJSON report written to: " << output_file << '\n';
    }
    return 0;
}

int open_dialer(const std::string& serial, const std::string& e164_number) {
    if (!valid_e164_number(e164_number)) {
        std::cerr << "Number must be E.164 format, e.g. +905321234567.\n";
        return 2;
    }
    if (!device_ready(serial)) return 2;
    const auto result = run_process({"adb", "-s", serial, "shell", "am", "start",
        "-a", "android.intent.action.DIAL", "-d", "tel:" + e164_number});
    std::cout << result.output;
    if (result.exit_code == 0) {
        std::cout << "Dialer opened on the selected phone. The call is NOT placed automatically; the user must review and tap Call.\n";
    }
    return result.exit_code;
}

int open_sms_composer(const std::string& serial, const std::string& e164_number) {
    if (!valid_e164_number(e164_number)) {
        std::cerr << "Number must be E.164 format, e.g. +905321234567.\n";
        return 2;
    }
    if (!device_ready(serial)) return 2;
    const auto result = run_process({"adb", "-s", serial, "shell", "am", "start",
        "-a", "android.intent.action.SENDTO", "-d", "smsto:" + e164_number});
    std::cout << result.output;
    if (result.exit_code == 0) {
        std::cout << "SMS composer opened on the selected phone. No message is sent automatically; the user must compose, review and tap Send.\n";
    }
    return result.exit_code;
}

int run_telecom_menu() {
    for (;;) {
        std::cout << "\n========== RFSEC 0.6 TELECOM / DEVICE ASSURANCE ==========" << '\n'
                  << "1. Discover connected Android devices (ADB)\n"
                  << "2. Inspect device and cellular status\n"
                  << "3. Run Android security-posture audit (JSON optional)\n"
                  << "4. Open native dialer for one authorized test call\n"
                  << "5. Open native SMS composer for one authorized test SMS\n"
                  << "6. Show passive HackRF RF-capture command\n"
                  << "7. Show offline protocol-parser fuzzing command\n"
                  << "8. Audit an operator-owned RAN/core config file\n"
                  << "9. Show private-network assessment checklist\n"
                  << "10. Audit exported cellular cell observations (CSV)\n"
                  << "11. Analyze passive IQ interference indicators\n"
                  << "12. Audit sanitized SMS/PBX gateway event logs\n"
                  << "0. Exit\n"
                  << "========================================================\n";
        const auto choice = read_line("Selection: ");
        if (choice == "0" || choice.empty()) return 0;
        if (choice == "1") {
            (void)list_devices();
        } else if (choice == "2") {
            const auto serial = read_line("ADB serial: ");
            (void)inspect_device(serial);
        } else if (choice == "3") {
            const auto serial = read_line("ADB serial: ");
            const auto report = read_line("JSON report path (blank for console only): ");
            (void)audit_device(serial, report);
        } else if (choice == "4") {
            const auto serial = read_line("ADB serial: ");
            const auto number = read_line("Authorized test destination (+countrycode...): ");
            (void)open_dialer(serial, number);
        } else if (choice == "5") {
            const auto serial = read_line("ADB serial: ");
            const auto number = read_line("Authorized test destination (+countrycode...): ");
            (void)open_sms_composer(serial, number);
        } else if (choice == "6") {
            std::cout << "Passive RX only. Use only frequencies and captures permitted in your jurisdiction:\n"
                      << "  rfsec capture --freq FREQUENCY_HZ --rate 2000000 --seconds 5 --out lab.iq8\n";
        } else if (choice == "7") {
            std::cout << "Offline parser testing example:\n"
                      << "  rfsec mutate --seed examples/seed_frame.bin --out corpus --count 500 --kind all --rng-seed 42\n";
        } else if (choice == "8") {
            const auto config = read_line("Path to operator-owned RAN/core config file: ");
            const auto report = read_line("JSON report path (blank for console only): ");
            if (config.empty()) std::cout << "No configuration file supplied.\n";
            else (void)rfsec::telecom::audit_config_file(config, report);
        } else if (choice == "10") {
            const auto input = read_line("Cell observations CSV path: ");
            const auto output = read_line("Findings CSV path (blank for console): ");
            const auto allow = read_line("PLMN allowlist (e.g. 286-01,234-15; blank disables allowlist): ");
            std::set<std::string> plmns;
            std::stringstream ss(allow); std::string item;
            while (std::getline(ss, item, ',')) if (!item.empty()) plmns.insert(item);
            if (!input.empty()) (void)rfsec::telecom::audit_cell_observations(input, output, plmns);
        } else if (choice == "11") {
            const auto input = read_line("Previously captured IQ8 file: ");
            const auto rate_text = read_line("Sample rate in samples/second: ");
            const auto output = read_line("Findings CSV path (blank for console): ");
            double rate = 0.0;
            try { rate = std::stod(rate_text); } catch (...) { rate = 0.0; }
            if (!input.empty() && rate > 0.0) {
                rfsec::telecom::InterferenceOptions options; options.sample_rate_hz = rate;
                (void)rfsec::telecom::audit_iq_interference(input, options, output);
            } else std::cout << "A valid IQ8 path and sample rate are required.\n";
        } else if (choice == "12") {
            const auto input = read_line("Sanitized SMS/PBX gateway event CSV path: ");
            const auto output = read_line("Findings CSV path (blank for console): ");
            if (!input.empty()) (void)rfsec::telecom::audit_comms_gateway_log(input, output);
        } else if (choice == "9") {
            std::cout << "Private LTE/5G assessment checklist:\n"
                      << "  - Use a private RAN/core you own or have written authorization to assess.\n"
                      << "  - Keep RF inside a shielded enclosure or use a conducted/attenuated setup.\n"
                      << "  - Register only test SIMs and test UEs; document the scope and maintenance window.\n"
                      << "  - Review AMF/MME authentication policy, subscriber provisioning, API access, TLS,\n"
                      << "    management-plane segmentation, logging, patching and backup/restore controls.\n"
                      << "  - Use vendor-supported management/test interfaces; preserve logs and rollback plans.\n"
                      << "RFSEC performs passive monitoring only; it does not impersonate public operators, jam cells, or inject OTA traffic.\n";
        } else {
            std::cout << "Unknown selection.\n";
        }
    }
}

} // namespace rfsec::android
