#pragma once

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace rfsec::telecom {

struct CommsAuditOptions {
    std::uint32_t window_seconds = 60;
    std::uint32_t max_events_per_actor = 20;
    std::uint32_t max_unique_peers_per_actor = 10;
};

struct CommsFinding {
    std::string severity;
    std::string code;
    std::string actor_token;
    std::uint64_t timestamp_ms = 0;
    std::string summary;
};

struct CommsAuditResult {
    std::size_t accepted_events = 0;
    std::size_t rejected_rows = 0;
    std::vector<CommsFinding> findings;
};

class CommsGatewayAuditor {
public:
    explicit CommsGatewayAuditor(CommsAuditOptions options = {}) : options_(options) {}
    int analyze(const std::filesystem::path& input_csv,
                const std::filesystem::path& output_csv = {},
                CommsAuditResult* result_out = nullptr) const;
private:
    CommsAuditOptions options_;
};

// Reads sanitized SMSC/PBX/gateway audit events. actor_token and peer_token must be
// 16-64 character hexadecimal keyed-HMAC tokens; raw phone numbers and message bodies
// are rejected. Schema: timestamp_ms,event_type,direction,actor_token,peer_token,
// auth_status,route_status,result.
int audit_comms_gateway_log(const std::filesystem::path& input_csv,
                            const std::filesystem::path& output_csv,
                            const CommsAuditOptions& options = {},
                            CommsAuditResult* result_out = nullptr);

} // namespace rfsec::telecom
