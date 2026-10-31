#include "rfsec/comms_audit.hpp"

#include <algorithm>
#include <charconv>
#include <cctype>
#include <deque>
#include <fstream>
#include <iostream>
#include <map>
#include <set>
#include <sstream>
#include <string_view>
#include <utility>
#include <vector>

namespace rfsec::telecom {
namespace {

std::vector<std::string> csv_row(std::string_view line) {
    std::vector<std::string> out;
    std::string field;
    bool quote = false;
    for (std::size_t i = 0; i < line.size(); ++i) {
        const char c = line[i];
        if (quote && c == '"' && i + 1 < line.size() && line[i + 1] == '"') {
            field += '"'; ++i;
        } else if (c == '"') quote = !quote;
        else if (c == ',' && !quote) { out.push_back(std::move(field)); field.clear(); }
        else field += c;
    }
    if (quote) return {};
    out.push_back(std::move(field));
    return out;
}

template<class T> bool number(std::string_view s, T& value) {
    T parsed{};
    const auto r = std::from_chars(s.data(), s.data() + s.size(), parsed);
    if (s.empty() || r.ec != std::errc{} || r.ptr != s.data() + s.size()) return false;
    value = parsed; return true;
}

bool safe_token(std::string_view s) {
    // Require a truncated/full HMAC-style hex token; this rejects E.164 numbers and names.
    if (s.size() < 16U || s.size() > 64U) return false;
    const bool hex_only = std::all_of(s.begin(), s.end(), [](unsigned char c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
    });
    const bool has_alpha = std::any_of(s.begin(), s.end(), [](unsigned char c) {
        return (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
    });
    return hex_only && has_alpha;
}

std::string quote_csv(std::string_view s) {
    if (s.find_first_of(",\"\r\n") == std::string_view::npos) return std::string(s);
    std::string o = "\"";
    for (char c : s) { if (c == '"') o += "\"\""; else o += c; }
    return o + '"';
}

struct Event {
    std::uint64_t time = 0;
    std::string type, direction, actor, peer, auth, route, result;
};

} // namespace

int audit_comms_gateway_log(const std::filesystem::path& input_csv,
                            const std::filesystem::path& output_csv,
                            const CommsAuditOptions& options,
                            CommsAuditResult* result_out) {
    if (options.window_seconds == 0U || options.window_seconds > 86400U ||
        options.max_events_per_actor == 0U || options.max_unique_peers_per_actor == 0U) {
        std::cerr << "Invalid comms audit thresholds.\n"; return 2;
    }
    std::ifstream in(input_csv);
    if (!in) { std::cerr << "Cannot open gateway audit CSV: " << input_csv << '\n'; return 2; }
    std::string line;
    if (!std::getline(in, line)) { std::cerr << "Gateway audit CSV is empty.\n"; return 2; }
    if (!line.empty() && line.back() == '\r') line.pop_back();
    const auto header = csv_row(line);
    const std::vector<std::string> required{"timestamp_ms","event_type","direction","actor_token","peer_token","auth_status","route_status","result"};
    std::map<std::string, std::size_t> col;
    for (std::size_t i = 0; i < header.size(); ++i) col[header[i]] = i;
    for (const auto& h : required) if (!col.contains(h)) {
        std::cerr << "Missing gateway audit column: " << h << '\n'; return 2;
    }
    std::vector<Event> events;
    CommsAuditResult report;
    while (std::getline(in, line)) {
        if (line.empty()) continue;
        if (!line.empty() && line.back() == '\r') line.pop_back();
        const auto fields = csv_row(line);
        bool enough = true;
        for (const auto& h : required) if (col[h] >= fields.size()) { enough = false; break; }
        Event e;
        if (!enough || !number(fields[col["timestamp_ms"]], e.time)) { ++report.rejected_rows; continue; }
        e.type = fields[col["event_type"]]; e.direction = fields[col["direction"]];
        e.actor = fields[col["actor_token"]]; e.peer = fields[col["peer_token"]];
        e.auth = fields[col["auth_status"]]; e.route = fields[col["route_status"]]; e.result = fields[col["result"]];
        if ((e.type != "SMS" && e.type != "CALL") || (e.direction != "IN" && e.direction != "OUT") ||
            !safe_token(e.actor) || !safe_token(e.peer) ||
            (e.auth != "verified" && e.auth != "unverified" && e.auth != "failed" && e.auth != "unknown") ||
            (e.route != "trusted" && e.route != "untrusted" && e.route != "unknown") ||
            (e.result != "success" && e.result != "failed" && e.result != "blocked")) {
            ++report.rejected_rows; continue;
        }
        events.push_back(std::move(e));
    }
    std::stable_sort(events.begin(), events.end(), [](const Event& a, const Event& b) { return a.time < b.time; });
    report.accepted_events = events.size();

    std::map<std::string, std::deque<const Event*>> actor_windows;
    for (const auto& e : events) {
        if (e.auth != "verified") {
            report.findings.push_back({"HIGH", "UNVERIFIED_OR_FAILED_ORIGIN", e.actor, e.time,
                "Gateway event has an origin authentication state other than verified; inspect provider authentication and signing logs."});
        }
        if (e.route != "trusted") {
            report.findings.push_back({"HIGH", "UNTRUSTED_ROUTE", e.actor, e.time,
                "Gateway event used a route not marked trusted by the local audit source."});
        }
        auto& q = actor_windows[e.actor];
        q.push_back(&e);
        const std::uint64_t window_ms = static_cast<std::uint64_t>(options.window_seconds) * 1000U;
        while (!q.empty() && e.time >= q.front()->time && e.time - q.front()->time > window_ms) q.pop_front();
        std::set<std::string> peers;
        for (const auto* item : q) peers.insert(item->peer);
        if (q.size() == static_cast<std::size_t>(options.max_events_per_actor) + 1U) {
            report.findings.push_back({"MEDIUM", "HIGH_EVENT_RATE", e.actor, e.time,
                "Actor exceeded the configured SMS/call event-rate threshold within the rolling window."});
        }
        if (peers.size() == static_cast<std::size_t>(options.max_unique_peers_per_actor) + 1U) {
            report.findings.push_back({"HIGH", "HIGH_RECIPIENT_FANOUT", e.actor, e.time,
                "Actor exceeded the configured unique-peer fan-out threshold within the rolling window; investigate for bulk abuse."});
        }
        if (e.result == "failed") {
            report.findings.push_back({"INFO", "FAILED_DELIVERY_OR_CALL", e.actor, e.time,
                "Gateway recorded a failed event. Correlate with delivery receipts and service availability logs."});
        }
    }

    std::ostream* out = &std::cout;
    std::ofstream csv;
    if (!output_csv.empty()) {
        csv.open(output_csv, std::ios::trunc);
        if (!csv) { std::cerr << "Cannot write comms audit report.\n"; return 2; }
        out = &csv;
    }
    *out << "severity,code,actor_token,timestamp_ms,summary\n";
    for (const auto& f : report.findings) {
        *out << f.severity << ',' << f.code << ',' << f.actor_token << ',' << f.timestamp_ms << ','
             << quote_csv(f.summary) << '\n';
    }
    std::cout << "Gateway event audit: accepted=" << report.accepted_events
              << " rejected=" << report.rejected_rows << " findings=" << report.findings.size() << '\n'
              << "Privacy: phone numbers, recipient addresses and message/call contents are not accepted by this schema.\n";
    if (!output_csv.empty()) std::cout << "Report: " << output_csv << '\n';
    const bool had_rejected_rows = report.rejected_rows > 0;
    if (result_out) *result_out = std::move(report);
    return had_rejected_rows ? 1 : 0;
}

int CommsGatewayAuditor::analyze(const std::filesystem::path& input_csv,
                                const std::filesystem::path& output_csv,
                                CommsAuditResult* result_out) const {
    return audit_comms_gateway_log(input_csv, output_csv, options_, result_out);
}

} // namespace rfsec::telecom
