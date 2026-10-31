#pragma once

#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

namespace rfsec::telecom {

struct ConfigIssue {
    std::string severity;
    std::string code;
    std::size_t line = 0;
    std::string summary;
};

// Heuristic, read-only checks for operator-owned RAN/core configuration files.
// Secret values and original config lines are never included in findings.
std::vector<ConfigIssue> analyze_config_text(std::string_view text);
int audit_config_file(const std::filesystem::path& input,
                      const std::filesystem::path& json_output = {});

} // namespace rfsec::telecom
