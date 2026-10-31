#include "rfsec/hackrf_capture.hpp"

#include <iostream>

namespace rfsec {

int capture_hackrf_rx(const CaptureOptions&) {
    std::cerr << "This RFSEC build does not include libhackrf. Install the libhackrf development package,\n"
                 "then re-run CMake. Offline analysis and mutation commands remain available.\n";
    return 3;
}

int capture_capability_status() {
    std::cout << "HackRF support: not built (libhackrf not found at configure time)\n";
    return 0;
}

} // namespace rfsec
