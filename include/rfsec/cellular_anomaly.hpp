#pragma once

#include <cstdint>
#include <filesystem>
#include <set>
#include <string>
#include <vector>

namespace rfsec::telecom {

// Sanitized, non-subscriber cellular broadcast/measurement metadata.
// Deliberately excludes IMSI, IMEI, MSISDN, authentication material and payloads.
struct CellObservation {
    std::uint64_t timestamp_ms = 0;
    std::string rat;       // GSM, UMTS, LTE, NR
    std::string mcc;
    std::string mnc;
    std::string tac;
    std::string cell_id;
    int pci = -1;
    std::uint32_t arfcn = 0; // ARFCN / EARFCN / NR-ARFCN, as provided by source
    double rsrp_dbm = 0.0;
    double rsrq_db = 0.0;
    std::string ciphering; // enabled, disabled, unknown, not_reported
};

struct CellFinding {
    std::string severity;
    std::string code;
    std::uint64_t timestamp_ms = 0;
    std::string summary;
};

struct CellAuditResult {
    std::size_t observations = 0;
    std::size_t rejected_rows = 0;
    std::vector<CellFinding> findings;
};

class CellAnomalyDetector {
public:
    explicit CellAnomalyDetector(std::set<std::string> allowed_plmns = {});
    [[nodiscard]] CellAuditResult analyze(const std::vector<CellObservation>& observations) const;

private:
    std::set<std::string> allowed_plmns_;
};

// CSV schema: timestamp_ms,rat,mcc,mnc,tac,cell_id,pci,arfcn,rsrp_dbm,rsrq_db,ciphering
int audit_cell_observations(const std::filesystem::path& input_csv,
                            const std::filesystem::path& output_csv,
                            const std::set<std::string>& allowed_plmns = {});

} // namespace rfsec::telecom
