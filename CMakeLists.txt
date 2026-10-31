cmake_minimum_required(VERSION 3.20)
project(rfsec_hackrf VERSION 0.6.0 LANGUAGES CXX)

option(RFSEC_ENABLE_TESTS "Build RFSEC tests" ON)
option(RFSEC_ENABLE_SANITIZERS "Enable AddressSanitizer and UndefinedBehaviorSanitizer" OFF)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(Threads REQUIRED)
find_package(PkgConfig QUIET)

add_library(rfsec_core
    src/iq_analyzer.cpp
    src/mutator.cpp
    src/telecom_config_audit.cpp
    src/cellular_anomaly.cpp
    src/interference_monitor.cpp
    src/comms_audit.cpp
)
target_include_directories(rfsec_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_compile_options(rfsec_core PRIVATE -Wall -Wextra -Wpedantic)

if(RFSEC_ENABLE_SANITIZERS AND CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(rfsec_core PUBLIC -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(rfsec_core PUBLIC -fsanitize=address,undefined)
endif()

set(RFSEC_HACKRF_FOUND FALSE)
if(PkgConfig_FOUND)
    pkg_check_modules(HACKRF QUIET IMPORTED_TARGET libhackrf)
    if(HACKRF_FOUND)
        set(RFSEC_HACKRF_FOUND TRUE)
    endif()
endif()

if(RFSEC_HACKRF_FOUND)
    add_library(rfsec_radio src/hackrf_capture.cpp)
    target_link_libraries(rfsec_radio PUBLIC PkgConfig::HACKRF Threads::Threads)
    target_include_directories(rfsec_radio PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
    target_compile_options(rfsec_radio PRIVATE -Wall -Wextra -Wpedantic)
    message(STATUS "RFSEC: libhackrf found; HackRF RX capture enabled")
else()
    add_library(rfsec_radio src/capture_stub.cpp)
    target_include_directories(rfsec_radio PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
    message(WARNING "libhackrf was not found: building offline-only RFSEC. Install libhackrf development files to enable capture.")
endif()

add_executable(rfsec src/main.cpp src/android_device.cpp)
target_link_libraries(rfsec PRIVATE rfsec_core rfsec_radio Threads::Threads)
target_include_directories(rfsec PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_compile_options(rfsec PRIVATE -Wall -Wextra -Wpedantic)

add_executable(frame_parser_demo examples/frame_parser_demo.cpp)
target_include_directories(frame_parser_demo PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_compile_options(frame_parser_demo PRIVATE -Wall -Wextra -Wpedantic)

if(RFSEC_ENABLE_TESTS)
    enable_testing()
    add_executable(rfsec_parser_tests tests/test_parser.cpp)
    target_include_directories(rfsec_parser_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
    add_test(NAME parser_unit_tests COMMAND rfsec_parser_tests)

    add_executable(rfsec_device_tests tests/test_android_device.cpp src/android_device.cpp)
    target_include_directories(rfsec_device_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
    target_link_libraries(rfsec_device_tests PRIVATE rfsec_core)
    target_compile_options(rfsec_device_tests PRIVATE -Wall -Wextra -Wpedantic)
    add_test(NAME android_number_validation_tests COMMAND rfsec_device_tests)

    add_executable(rfsec_telecom_config_tests tests/test_telecom_config_audit.cpp)
    target_link_libraries(rfsec_telecom_config_tests PRIVATE rfsec_core)
    add_test(NAME telecom_config_audit_tests COMMAND rfsec_telecom_config_tests)

    add_executable(rfsec_cellular_anomaly_tests tests/test_cellular_anomaly.cpp)
    target_link_libraries(rfsec_cellular_anomaly_tests PRIVATE rfsec_core)
    add_test(NAME cellular_anomaly_tests COMMAND rfsec_cellular_anomaly_tests)

    add_executable(rfsec_comms_audit_tests tests/test_comms_audit.cpp)
    target_link_libraries(rfsec_comms_audit_tests PRIVATE rfsec_core)
    add_test(NAME comms_audit_tests COMMAND rfsec_comms_audit_tests)

    add_executable(rfsec_interference_tests tests/test_interference_monitor.cpp)
    target_link_libraries(rfsec_interference_tests PRIVATE rfsec_core)
    add_test(NAME passive_interference_tests COMMAND rfsec_interference_tests)
endif()

message(STATUS "RFSEC version: ${PROJECT_VERSION}")
message(STATUS "RFSEC transmission support: intentionally absent")
