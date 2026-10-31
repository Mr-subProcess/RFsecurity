#include "rfsec/comms_audit.hpp"

#include <cassert>
#include <filesystem>
#include <fstream>
#include <iostream>

int main() {
    using namespace rfsec::telecom;
    const auto path = std::filesystem::temp_directory_path() / "rfsec_comms_audit_test.csv";
    {
        std::ofstream out(path);
        out << "timestamp_ms,event_type,direction,actor_token,peer_token,auth_status,route_status,result\n";
        out << "1000,SMS,OUT,a1b2c3d4e5f60718,abcd222233334444,verified,trusted,success\n";
        out << "1100,CALL,OUT,a1b2c3d4e5f60718,bcde333344445555,unverified,untrusted,failed\n";
        out << "1200,SMS,OUT,a1b2c3d4e5f60718,cdef444455556666,verified,trusted,success\n";
        out << "1300,SMS,OUT,905555000000,abcd555566667777,verified,trusted,success\n";
    }
    CommsAuditOptions options; options.window_seconds = 60; options.max_events_per_actor = 1; options.max_unique_peers_per_actor = 1;
    CommsAuditResult result;
    CommsGatewayAuditor auditor(options);
    const int rc = auditor.analyze(path, {}, &result);
    assert(rc == 1); // the raw numeric recipient/actor token row must be rejected
    assert(result.accepted_events == 3);
    assert(result.rejected_rows == 1);
    bool fanout = false, auth = false, route = false, rate = false;
    for (const auto& f : result.findings) {
        fanout |= f.code == "HIGH_RECIPIENT_FANOUT";
        auth |= f.code == "UNVERIFIED_OR_FAILED_ORIGIN";
        route |= f.code == "UNTRUSTED_ROUTE";
        rate |= f.code == "HIGH_EVENT_RATE";
    }
    assert(fanout && auth && route && rate);
    std::filesystem::remove(path);
    std::cout << "comms audit tests passed\n";
}
