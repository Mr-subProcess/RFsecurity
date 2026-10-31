#include "rfsec/telecom_config_audit.hpp"

#include <iostream>
#include <string>

#define CHECK(condition) do { \
    if (!(condition)) { \
        std::cerr << "CHECK failed at " << __FILE__ << ':' << __LINE__ \
                  << ": " #condition << '\n'; \
        return 1; \
    } \
} while (false)

int main() {
    const std::string sample = R"CFG(
# comment: auth_enabled: false
management:
  bind_address: 0.0.0.0
  endpoint: http://127.0.0.1:8080/admin
security:
  verify_peer: false
  auth_required: false
  api_token: changeme
logging:
  debug: true
)CFG";
    const auto findings = rfsec::telecom::analyze_config_text(sample);
    const auto has = [&](const std::string& code) {
        for (const auto& f : findings) if (f.code == code) return true;
        return false;
    };
    CHECK(has("WIDE_BIND"));
    CHECK(has("PLAINTEXT_HTTP"));
    CHECK(has("TLS_VERIFICATION_DISABLED"));
    CHECK(has("AUTH_DISABLED"));
    CHECK(has("WEAK_DEFAULT_SECRET"));
    CHECK(has("DEBUG_LOGGING"));

    const auto clean = rfsec::telecom::analyze_config_text(
        "management:\n  bind_address: 127.0.0.1\n  endpoint: https://localhost/admin\n  auth_required: true\n");
    CHECK(clean.empty());
    std::cout << "All telecom config audit tests passed.\n";
    return 0;
}
