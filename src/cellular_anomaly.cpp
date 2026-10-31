#include "rfsec/cellular_anomaly.hpp"

#include <algorithm>
#include <charconv>
#include <cmath>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <optional>
#include <sstream>
#include <string_view>
#include <tuple>
#include <unordered_map>

namespace rfsec::telecom {
namespace {

std::vector<std::string> parse_csv_row(std::string_view line) {
    std::vector<std::string> fields;
    std::string field;
    bool quoted = false;
    for (std::size_t i = 0; i < line.size(); ++i) {
        const char c = line[i];
        if (quoted) {
            if (c == '"' && i + 1 < line.size() && line[i + 1] == '"') {
                field.push_back('"'); ++i;
            } else if (c == '"') {
                quoted = false;
            } else field.push_back(c);
        } else if (c == '"') {
            quoted = true;
        } else if (c == ',') {
            fields.push_back(std::move(field)); field.clear();
        } else {
            field.push_back(c);
        }
    }
    if (quoted) return {};
    fields.push_back(std::move(field));
    return fields;
}

template <typename T>
bool parse_integer(std::string_view value, T& out) {
    if (value.empty()) return false;
    T parsed{};
    const auto result = std::from_chars(value.data(), value.data() + value.size(), parsed);
    if (result.ec != std::errc{} || result.ptr != value.data() + value.size()) return false;
    out = parsed;
    return true;
}

bool parse_real(std::string_view value, double& out) {
    try {
        std::size_t used = 0;
        const double parsed = std::stod(std::string(value), &used);
        if (used != value.size() || !std::isfinite(parsed)) return false;
        out = parsed;
        return true;
    } catch (...) { return false; }
}

std::string csv_escape(std::string_view value) {
    if (value.find_first_of(",\"\r\n") == std::string_view::npos) return std::string(value);
    std::string out = "\"";
    for (char c : value) { if (c == '"') out += "\"\""; else out += c; }
    out += '"';
    return out;
}

bool valid_digits(std::string_view s, std::size_t min_len, std::size_t max_len) {
    return s.size() >= min_len && s.size() <= max_len &&
        std::all_of(s.begin(), s.end(), [](unsigned char c) { return c >= '0' && c <= '9'; });
}

bool valid_observation(const CellObservation& o) {
    const auto rat_ok = o.rat == "GSM" || o.rat == "UMTS" || o.rat == "LTE" || o.rat == "NR";
    const auto cipher_ok = o.ciphering == "enabled" || o.ciphering == "disabled" ||
                           o.ciphering == "unknown" || o.ciphering == "not_reported";
    return o.timestamp_ms > 0 && rat_ok && valid_digits(o.mcc, 3, 3) &&
           valid_digits(o.mnc, 2, 3) && !o.tac.empty() && o.tac.size() <= 32 &&
           !o.cell_id.empty() && o.cell_id.size() <= 32 && o.pci >= 0 && o.pci <= 1007 &&
           o.arfcn > 0 && std::isfinite(o.rsrp_dbm) && o.rsrp_dbm >= -160.0 && o.rsrp_dbm <= 0.0 &&
           std::isfinite(o.rsrq_db) && o.rsrq_db >= -50.0 && o.rsrq_db <= 10.0 && cipher_ok;
}

} // namespace

CellAnomalyDetector::CellAnomalyDetector(std::set<std::string> allowed_plmns)
    : allowed_plmns_(std::move(allowed_plmns)) {}

CellAuditResult CellAnomalyDetector::analyze(const std::vector<CellObservation>& input) const {
    CellAuditResult result;
    std::vector<CellObservation> observations;
    observations.reserve(input.size());
    for (const auto& o : input) {
        if (!valid_observation(o)) { ++result.rejected_rows; continue; }
        observations.push_back(o);
    }
    std::stable_sort(observations.begin(), observations.end(), [](const auto& a, const auto& b) {
        return a.timestamp_ms < b.timestamp_ms;
    });
    result.observations = observations.size();

    struct SeenCell { std::string cell_id; std::uint64_t timestamp_ms; };
    std::map<std::tuple<std::string, std::uint32_t, int>, SeenCell> pci_seen;
    std::map<std::pair<std::string, std::uint32_t>, CellObservation> channel_seen;
    std::map<std::pair<std::string, std::uint32_t>, std::uint64_t> previous_tac_time;

    for (const auto& o : observations) {
        const std::string plmn = o.mcc + "-" + o.mnc;
        if (!allowed_plmns_.empty() && !allowed_plmns_.contains(plmn)) {
            result.findings.push_back({"HIGH", "UNAPPROVED_PLMN", o.timestamp_ms,
                "Observed PLMN is not in the configured allowlist: " + plmn + ". Verify the measurement source and serving-network identity."});
        }
        if (o.ciphering == "disabled") {
            result.findings.push_back({"HIGH", "CIPHERING_REPORTED_DISABLED", o.timestamp_ms,
                "Measurement source reports ciphering disabled. Confirm this state using trusted operator diagnostics; broadcast metadata alone may not prove user-plane protection status."});
        }
        if (o.rsrp_dbm > -45.0) {
            result.findings.push_back({"INFO", "VERY_STRONG_CELL_SIGNAL", o.timestamp_ms,
                "Very strong received signal level (> -45 dBm). This can be legitimate at close range; correlate with location and trusted cell inventory."});
        }

        const auto pci_key = std::make_tuple(o.rat, o.arfcn, o.pci);
        auto p = pci_seen.find(pci_key);
        if (p != pci_seen.end() && p->second.cell_id != o.cell_id &&
            o.timestamp_ms >= p->second.timestamp_ms &&
            o.timestamp_ms - p->second.timestamp_ms <= 300'000U) {
            result.findings.push_back({"MEDIUM", "PCI_IDENTITY_COLLISION", o.timestamp_ms,
                "Different cell identities were observed with the same RAT, channel and PCI within five minutes. PCI reuse is possible; validate against a geospatial/operator inventory."});
        }
        pci_seen[pci_key] = {o.cell_id, o.timestamp_ms};

        const auto channel_key = std::make_pair(o.rat, o.arfcn);
        auto ch = channel_seen.find(channel_key);
        if (ch != channel_seen.end()) {
            const auto& old = ch->second;
            if (o.timestamp_ms >= old.timestamp_ms && o.timestamp_ms - old.timestamp_ms <= 120'000U &&
                (o.cell_id != old.cell_id || o.mcc != old.mcc || o.mnc != old.mnc) &&
                o.rsrp_dbm > -85.0 && old.rsrp_dbm > -85.0) {
                result.findings.push_back({"MEDIUM", "RAPID_CELL_IDENTITY_CHANGE", o.timestamp_ms,
                    "Cell identity or PLMN changed on the same RAT/channel within two minutes while both signals were strong. Could indicate normal mobility or an anomalous cell; corroborate with trusted measurements."});
            }
            if (o.tac != old.tac && o.timestamp_ms >= old.timestamp_ms &&
                o.timestamp_ms - old.timestamp_ms <= 30'000U) {
                result.findings.push_back({"INFO", "RAPID_TAC_CHANGE", o.timestamp_ms,
                    "Tracking-area identity changed within 30 seconds. Mobility and measurement-source behavior can explain this; inspect the event timeline."});
            }
        }
        channel_seen[channel_key] = o;
    }
    return result;
}

int audit_cell_observations(const std::filesystem::path& input_csv,
                            const std::filesystem::path& output_csv,
                            const std::set<std::string>& allowed_plmns) {
    std::ifstream in(input_csv);
    if (!in) { std::cerr << "Cannot open cell observation CSV: " << input_csv << '\n'; return 2; }
    std::string line;
    if (!std::getline(in, line)) { std::cerr << "Cell observation CSV is empty.\n"; return 2; }
    if (!line.empty() && line.back() == '\r') line.pop_back();
    const auto header = parse_csv_row(line);
    const std::vector<std::string> required{"timestamp_ms","rat","mcc","mnc","tac","cell_id","pci","arfcn","rsrp_dbm","rsrq_db","ciphering"};
    std::map<std::string, std::size_t> cols;
    for (std::size_t i = 0; i < header.size(); ++i) cols[header[i]] = i;
    for (const auto& name : required) if (!cols.contains(name)) {
        std::cerr << "Missing required cell CSV column: " << name << '\n'; return 2;
    }
    std::vector<CellObservation> rows;
    std::size_t rejected = 0;
    while (std::getline(in, line)) {
        if (line.empty()) continue;
        if (!line.empty() && line.back() == '\r') line.pop_back();
        const auto f = parse_csv_row(line);
        if (f.empty()) { ++rejected; continue; }
        bool row_complete = true;
        for (const auto& name : required) {
            if (cols[name] >= f.size()) { row_complete = false; break; }
        }
        if (!row_complete) { ++rejected; continue; }
        CellObservation o;
        std::uint32_t arfcn = 0;
        if (!parse_integer(f[cols["timestamp_ms"]], o.timestamp_ms) ||
            !parse_integer(f[cols["pci"]], o.pci) ||
            !parse_integer(f[cols["arfcn"]], arfcn) ||
            !parse_real(f[cols["rsrp_dbm"]], o.rsrp_dbm) ||
            !parse_real(f[cols["rsrq_db"]], o.rsrq_db)) { ++rejected; continue; }
        o.arfcn = arfcn;
        o.rat = f[cols["rat"]]; o.mcc = f[cols["mcc"]]; o.mnc = f[cols["mnc"]];
        o.tac = f[cols["tac"]]; o.cell_id = f[cols["cell_id"]]; o.ciphering = f[cols["ciphering"]];
        rows.push_back(std::move(o));
    }
    CellAnomalyDetector detector(allowed_plmns);
    auto report = detector.analyze(rows);
    report.rejected_rows += rejected;

    std::ostream* out = &std::cout;
    std::ofstream file;
    if (!output_csv.empty()) {
        file.open(output_csv, std::ios::trunc);
        if (!file) { std::cerr << "Cannot write cell audit CSV: " << output_csv << '\n'; return 2; }
        out = &file;
    }
    *out << "severity,code,timestamp_ms,summary\n";
    for (const auto& finding : report.findings) {
        *out << finding.severity << ',' << finding.code << ',' << finding.timestamp_ms << ','
             << csv_escape(finding.summary) << '\n';
    }
    std::cout << "Cellular passive audit: accepted=" << report.observations
              << " rejected=" << report.rejected_rows
              << " findings=" << report.findings.size() << '\n';
    if (report.findings.empty()) std::cout << "No configured anomaly rules were triggered. This is not proof of a safe or genuine cell.\n";
    if (!output_csv.empty()) std::cout << "Report: " << output_csv << '\n';
    return report.rejected_rows > 0 ? 1 : 0;
}

} // namespace rfsec::telecom
