#pragma once

#include <string>
#include <string_view>

namespace rfsec::android {

// E.164 validation: '+' followed by 7..15 decimal digits.
bool valid_e164_number(std::string_view number) noexcept;

int list_devices();
int inspect_device(const std::string& serial);
int audit_device(const std::string& serial, const std::string& output_file = {});
int open_dialer(const std::string& serial, const std::string& e164_number);
int open_sms_composer(const std::string& serial, const std::string& e164_number);
int run_telecom_menu();

} // namespace rfsec::android
