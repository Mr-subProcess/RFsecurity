#include "rfsec/android_device.hpp"

#include <iostream>

#define CHECK(condition) do { \
    if (!(condition)) { \
        std::cerr << "CHECK failed at " << __FILE__ << ':' << __LINE__ \
                  << ": " #condition << '\n'; \
        return 1; \
    } \
} while (false)

int main() {
    CHECK(rfsec::android::valid_e164_number("+905321234567"));
    CHECK(rfsec::android::valid_e164_number("+12025550123"));
    CHECK(!rfsec::android::valid_e164_number("05321234567"));
    CHECK(!rfsec::android::valid_e164_number("+90 532 123 45 67"));
    CHECK(!rfsec::android::valid_e164_number("+90;touch /tmp/pwn"));
    CHECK(!rfsec::android::valid_e164_number("+123"));
    CHECK(!rfsec::android::valid_e164_number("+1234567890123456"));
    CHECK(!rfsec::android::valid_e164_number(""));
    std::cout << "All Android device input validation tests passed.\n";
    return 0;
}
