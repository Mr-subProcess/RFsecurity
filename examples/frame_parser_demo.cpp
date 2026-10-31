#include "rfsec/frame_parser.hpp"

#include <cstdint>
#include <iostream>
#include <iterator>
#include <vector>

int main() {
    const std::istreambuf_iterator<char> begin(std::cin);
    const std::istreambuf_iterator<char> end;
    std::vector<std::uint8_t> input(begin, end);
    const auto result = rfsec::frame::parse(input);
    std::cout << rfsec::frame::to_string(result) << '\n';
    return result == rfsec::frame::ParseResult::Ok ? 0 : 1;
}
