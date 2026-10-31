#pragma once

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace rfsec {

enum class MutationKind {
    All, Bitflip, Truncate, Extend, Duplicate, Zero,
    Insert, Erase, Boundary, Shuffle, DeclaredLength
};

[[nodiscard]] bool parse_mutation_kind(const std::string& text, MutationKind& out);
[[nodiscard]] std::vector<std::string> mutation_kind_names();

int generate_corpus(const std::filesystem::path& seed_file,
                    const std::filesystem::path& output_dir,
                    std::uint64_t count,
                    MutationKind kind,
                    std::uint64_t seed,
                    std::size_t max_size);

} // namespace rfsec
