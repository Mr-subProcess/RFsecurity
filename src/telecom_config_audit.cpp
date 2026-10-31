#include "rfsec/telecom_config_audit.hpp"

#include <algorithm>
#include <cctype>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <system_error>

namespace rfsec::telecom {
namespace {

std::string lower(std::string_view value) {
    std::string out(value);
    std::transform(out.begin(), out.end(), out.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return out;
}

std::string trim(std::string value) {
    const auto first = value.find_first_not_of(" \t\r\n\"");
    if (first == std::string::npos) return {};
    const auto last = value.find_last_not_of(" \t\r\n\"");
    value = value.substr(first, last - first + 1U);
    if (!value.empty() && value.back() == '\'') value.pop_back();
    if (!value.empty() && value.front() == '\'') value.erase(value.begin());
    return value;
}

std::string json_escape(std::string_view input) {
    std::string out;
    out.reserve(input.size() + 8U);
    for (const unsigned char c : input) {
        switch (c) {
            case '\\': out += "\\\\"; break;
            case '"': out += "\\\""; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default: if (c < 0x20) out += '?'; else out += static_cast<char>(c);
        }
    }
    return out;
}

void push(std::vector<ConfigIssue>& issues, std::string severity,
          std::string code, std::size_t line, std::string summary) {
    if (issues.size() < 200U) issues.push_back({std::move(severity), std::move(code), line, std::move(summary)});
}

} // namespace

std::vector<ConfigIssue> analyze_config_text(std::string_view text) {
    std::vector<ConfigIssue> issues;
    std::istringstream input{std::string(text)};
    std::string line;
    std::size_t line_number = 0;

    while (std::getline(input, line)) {
        ++line_number;
        const auto cleaned = trim(line);
        if (cleaned.empty() || cleaned.front() == '#' || cleaned.rfind("//", 0) == 0) continue;
        const auto l = lower(cleaned);

        const bool has_bind_context = l.find("bind") != std::string::npos ||
            l.find("listen") != std::string::npos || l.find("address") != std::string::npos ||
            l.find("interface") != std::string::npos || l.find("host") != std::string::npos;
        const auto bind_delimiter = l.find_first_of(":=");
        const auto bind_value = bind_delimiter == std::string::npos
            ? std::string{} : trim(l.substr(bind_delimiter + 1U));
        if (has_bind_context && (bind_value == "0.0.0.0" || bind_value == "::" ||
                                 bind_value == "[::]" || bind_value == "\"0.0.0.0\"" ||
                                 bind_value == "\"::\"")) {
            push(issues, "WARN", "WIDE_BIND", line_number,
                 "A listener appears bound to all interfaces; verify firewalling and management-plane isolation.");
        }

        if (l.find("http://") != std::string::npos &&
            (has_bind_context || l.find("management") != std::string::npos ||
             l.find("endpoint") != std::string::npos || l.find("url") != std::string::npos)) {
            push(issues, "WARN", "PLAINTEXT_HTTP", line_number,
                 "A management or service endpoint appears to use plaintext HTTP.");
        }

        if (l.find("verify_peer: false") != std::string::npos ||
            l.find("verify_tls: false") != std::string::npos ||
            l.find("insecure_skip_verify: true") != std::string::npos ||
            l.find("tls_enabled: false") != std::string::npos ||
            l.find("ssl_enabled: false") != std::string::npos ||
            l.find("verify_certificate: false") != std::string::npos) {
            push(issues, "HIGH", "TLS_VERIFICATION_DISABLED", line_number,
                 "TLS/certificate verification appears disabled.");
        }

        if (l.find("auth_required: false") != std::string::npos ||
            l.find("authentication: none") != std::string::npos ||
            l.find("auth_enabled: false") != std::string::npos) {
            push(issues, "HIGH", "AUTH_DISABLED", line_number,
                 "An authentication control appears disabled or set to none.");
        }

        const bool secret_key = l.find("password") != std::string::npos ||
            l.find("passwd") != std::string::npos || l.find("secret") != std::string::npos ||
            l.find("api_key") != std::string::npos || l.find("token") != std::string::npos ||
            l.find("shared_key") != std::string::npos;
        const auto delimiter = l.find_first_of(":=");
        if (secret_key && delimiter != std::string::npos) {
            const auto secret_value = trim(l.substr(delimiter + 1U));
            if (secret_value.empty() || secret_value == "null" || secret_value == "none" ||
                secret_value == "\"\"" || secret_value == "''") {
                push(issues, "HIGH", "EMPTY_SECRET", line_number,
                     "A credential/secret field appears empty or unset.");
            } else if (secret_value == "password" || secret_value == "admin" ||
                       secret_value == "changeme" || secret_value == "123456" ||
                       secret_value == "12345678" || secret_value == "test") {
                push(issues, "HIGH", "WEAK_DEFAULT_SECRET", line_number,
                     "A well-known default/test credential value appears to be configured.");
            }
        }

        if ((l.find("debug: true") != std::string::npos ||
             l.find("log_level: trace") != std::string::npos ||
             l.find("log_level: debug") != std::string::npos)) {
            push(issues, "INFO", "DEBUG_LOGGING", line_number,
                 "Verbose/debug logging is enabled; confirm logs do not expose subscriber data or secrets.");
        }
    }
    return issues;
}

int audit_config_file(const std::filesystem::path& input,
                      const std::filesystem::path& json_output) {
    std::error_code ec;
    const auto size = std::filesystem::file_size(input, ec);
    if (ec || size > 4U * 1024U * 1024U) {
        std::cerr << "Cannot read configuration or file exceeds 4 MiB: " << input << '\n';
        return 2;
    }
    std::ifstream in(input, std::ios::binary);
    if (!in) {
        std::cerr << "Cannot open configuration file: " << input << '\n';
        return 2;
    }
    const std::string content{std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
    auto issues = analyze_config_text(content);

    std::string file_permission_issue;
    const auto perms = std::filesystem::status(input, ec).permissions();
    if (!ec) {
        using P = std::filesystem::perms;
        if ((perms & P::others_write) != P::none || (perms & P::group_write) != P::none) {
            issues.push_back({"HIGH", "CONFIG_WRITABLE_BY_OTHERS", 0,
                "Configuration file is writable by group/other users; restrict file permissions."});
        } else if ((perms & P::others_read) != P::none) {
            issues.push_back({"WARN", "CONFIG_WORLD_READABLE", 0,
                "Configuration file is readable by all local users; check for embedded credentials."});
        }
    }

    const auto count = [&](std::string_view severity) {
        return std::count_if(issues.begin(), issues.end(), [&](const ConfigIssue& issue) {
            return issue.severity == severity;
        });
    };
    const auto high = count("HIGH");
    const auto warn = count("WARN");
    const auto overall = high > 0 ? "HIGH_RISK_FINDINGS" : (warn > 0 ? "REVIEW_REQUIRED" : "NO_HIGH_OR_WARN_FINDINGS");

    std::cout << "RFSEC RAN/Core Configuration Audit (heuristic, read-only)\n"
              << "File: " << input.string() << "\n"
              << "Overall: " << overall << " | HIGH=" << high << " WARN=" << warn
              << " INFO=" << count("INFO") << '\n';
    if (issues.empty()) {
        std::cout << "No configured heuristic checks matched. This is not proof of a secure configuration.\n";
    }
    for (const auto& issue : issues) {
        std::cout << '[' << issue.severity << "] " << issue.code;
        if (issue.line != 0) std::cout << " (line " << issue.line << ')';
        std::cout << ": " << issue.summary << '\n';
    }
    std::cout << "Secret values and original config lines are intentionally not displayed.\n"
              << "Heuristic note: review each finding against the vendor's documented deployment model.\n";

    if (!json_output.empty()) {
        std::ofstream out(json_output, std::ios::binary | std::ios::trunc);
        if (!out) {
            std::cerr << "Cannot write JSON report: " << json_output << '\n';
            return 2;
        }
        out << "{\n  \"tool\": \"RFSEC\",\n  \"version\": \"0.5.0\",\n"
            << "  \"audit_type\": \"read_only_ran_core_config_heuristics\",\n"
            << "  \"input\": \"" << json_escape(input.filename().string()) << "\",\n"
            << "  \"overall\": \"" << overall << "\",\n  \"findings\": [\n";
        for (std::size_t i = 0; i < issues.size(); ++i) {
            const auto& issue = issues[i];
            out << "    {\"severity\":\"" << json_escape(issue.severity)
                << "\",\"code\":\"" << json_escape(issue.code)
                << "\",\"line\":" << issue.line
                << ",\"summary\":\"" << json_escape(issue.summary) << "\"}"
                << (i + 1U == issues.size() ? "\n" : ",\n");
        }
        out << "  ]\n}\n";
        if (!out) {
            std::cerr << "Failed while writing JSON report.\n";
            return 2;
        }
        std::cout << "JSON report: " << json_output.string() << '\n';
    }
    return high > 0 ? 1 : 0;
}

} // namespace rfsec::telecom
