#include "rfsec/mutator.hpp"

#include <algorithm>
#include <array>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <random>
#include <sstream>

namespace rfsec {
namespace {

constexpr std::size_t kAbsoluteMaxCaseBytes = 1024U * 1024U;
constexpr std::uint64_t kAbsoluteMaxCorpusBytes = 512ULL * 1024ULL * 1024ULL;

MutationKind mutate(std::vector<std::uint8_t>& data, MutationKind kind,
                     std::mt19937_64& rng, std::size_t max_size) {
    if (kind == MutationKind::All) {
        static constexpr std::array<MutationKind, 9> choices = {
            MutationKind::Bitflip, MutationKind::Truncate, MutationKind::Extend,
            MutationKind::Duplicate, MutationKind::Zero, MutationKind::Insert,
            MutationKind::Erase, MutationKind::Boundary, MutationKind::Shuffle
        };
        std::uniform_int_distribution<std::size_t> pick(0, choices.size() - 1);
        kind = choices[pick(rng)];
    }

    auto random_byte = [&]() {
        return static_cast<std::uint8_t>(std::uniform_int_distribution<unsigned>(0, 255)(rng));
    };

    if (kind == MutationKind::Bitflip && !data.empty()) {
        std::uniform_int_distribution<std::size_t> pos(0, data.size() - 1);
        std::uniform_int_distribution<int> bit(0, 7);
        std::uniform_int_distribution<int> flips(1, 8);
        const int n = flips(rng);
        for (int k = 0; k < n; ++k) data[pos(rng)] ^= static_cast<std::uint8_t>(1U << bit(rng));
    } else if (kind == MutationKind::Truncate && !data.empty()) {
        std::uniform_int_distribution<std::size_t> len(0, data.size() - 1);
        data.resize(len(rng));
    } else if (kind == MutationKind::Extend && data.size() < max_size) {
        const std::size_t room = max_size - data.size();
        std::uniform_int_distribution<std::size_t> amount(1, std::min<std::size_t>(256, room));
        const auto extra = amount(rng);
        data.reserve(data.size() + extra);
        for (std::size_t n = 0; n < extra; ++n) data.push_back(random_byte());
    } else if (kind == MutationKind::Duplicate && !data.empty() && data.size() < max_size) {
        const std::size_t block_max = std::min<std::size_t>({64, data.size(), max_size - data.size()});
        if (block_max == 0) return kind;
        const auto block = std::uniform_int_distribution<std::size_t>(1, block_max)(rng);
        const auto start = std::uniform_int_distribution<std::size_t>(0, data.size() - block)(rng);
        const auto destination = std::uniform_int_distribution<std::size_t>(0, data.size())(rng);
        const std::vector<std::uint8_t> copy(data.begin() + static_cast<std::ptrdiff_t>(start),
                                             data.begin() + static_cast<std::ptrdiff_t>(start + block));
        data.insert(data.begin() + static_cast<std::ptrdiff_t>(destination), copy.begin(), copy.end());
    } else if (kind == MutationKind::Zero && !data.empty()) {
        const auto start = std::uniform_int_distribution<std::size_t>(0, data.size() - 1)(rng);
        const auto len = std::uniform_int_distribution<std::size_t>(1, data.size() - start)(rng);
        std::fill(data.begin() + static_cast<std::ptrdiff_t>(start),
                  data.begin() + static_cast<std::ptrdiff_t>(start + len), 0);
    } else if (kind == MutationKind::Insert && data.size() < max_size) {
        const auto room = max_size - data.size();
        const auto amount = std::uniform_int_distribution<std::size_t>(1, std::min<std::size_t>(32, room))(rng);
        const auto at = std::uniform_int_distribution<std::size_t>(0, data.size())(rng);
        std::vector<std::uint8_t> bytes(amount);
        std::generate(bytes.begin(), bytes.end(), random_byte);
        data.insert(data.begin() + static_cast<std::ptrdiff_t>(at), bytes.begin(), bytes.end());
    } else if (kind == MutationKind::Erase && !data.empty()) {
        const auto start = std::uniform_int_distribution<std::size_t>(0, data.size() - 1)(rng);
        const auto len = std::uniform_int_distribution<std::size_t>(1, data.size() - start)(rng);
        data.erase(data.begin() + static_cast<std::ptrdiff_t>(start),
                   data.begin() + static_cast<std::ptrdiff_t>(start + len));
    } else if (kind == MutationKind::Boundary) {
        // Exercise common integer and parser boundary values in arbitrary byte positions.
        static constexpr std::array<std::uint8_t, 12> values = {
            0x00, 0x01, 0x7f, 0x80, 0xfe, 0xff,
            0x00, 0xff, 0x01, 0x00, 0x7f, 0x80
        };
        if (data.empty() && max_size > 0) data.push_back(random_byte());
        if (!data.empty()) {
            const auto pos = std::uniform_int_distribution<std::size_t>(0, data.size() - 1)(rng);
            data[pos] = values[std::uniform_int_distribution<std::size_t>(0, values.size() - 1)(rng)];
        }
    } else if (kind == MutationKind::Shuffle && data.size() > 1) {
        const auto start = std::uniform_int_distribution<std::size_t>(0, data.size() - 2)(rng);
        const auto end = std::uniform_int_distribution<std::size_t>(start + 1, data.size() - 1)(rng);
        std::shuffle(data.begin() + static_cast<std::ptrdiff_t>(start),
                     data.begin() + static_cast<std::ptrdiff_t>(end + 1), rng);
    } else if (kind == MutationKind::DeclaredLength && data.size() >= 5 &&
               data[0] == 0x52 && data[1] == 0x46 && data[2] == 1) {
        // RFSEC demonstration format only: bytes [3,4] encode a big-endian u16 length.
        static constexpr std::array<std::uint16_t, 8> lengths = {
            0, 1, 1023, 1024, 1025, 2048, 4096, 65535
        };
        const auto value = lengths[std::uniform_int_distribution<std::size_t>(0, lengths.size() - 1)(rng)];
        data[3] = static_cast<std::uint8_t>((value >> 8U) & 0xffU);
        data[4] = static_cast<std::uint8_t>(value & 0xffU);
    }
    return kind;
}

const char* mutation_name(MutationKind kind) {
    switch (kind) {
        case MutationKind::Bitflip: return "bitflip";
        case MutationKind::Truncate: return "truncate";
        case MutationKind::Extend: return "extend";
        case MutationKind::Duplicate: return "duplicate";
        case MutationKind::Zero: return "zero";
        case MutationKind::Insert: return "insert";
        case MutationKind::Erase: return "erase";
        case MutationKind::Boundary: return "boundary";
        case MutationKind::Shuffle: return "shuffle";
        case MutationKind::DeclaredLength: return "declared_length";
        case MutationKind::All: return "all";
    }
    return "unknown";
}

bool write_binary(const std::filesystem::path& path, const std::vector<std::uint8_t>& data) {
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out) return false;
    if (!data.empty()) out.write(reinterpret_cast<const char*>(data.data()),
                                 static_cast<std::streamsize>(data.size()));
    return static_cast<bool>(out);
}

} // namespace

bool parse_mutation_kind(const std::string& text, MutationKind& out) {
    if (text == "all") out = MutationKind::All;
    else if (text == "bitflip") out = MutationKind::Bitflip;
    else if (text == "truncate") out = MutationKind::Truncate;
    else if (text == "extend") out = MutationKind::Extend;
    else if (text == "duplicate") out = MutationKind::Duplicate;
    else if (text == "zero") out = MutationKind::Zero;
    else if (text == "insert") out = MutationKind::Insert;
    else if (text == "erase") out = MutationKind::Erase;
    else if (text == "boundary") out = MutationKind::Boundary;
    else if (text == "shuffle") out = MutationKind::Shuffle;
    else if (text == "length") out = MutationKind::DeclaredLength;
    else return false;
    return true;
}

std::vector<std::string> mutation_kind_names() {
    return {"all", "bitflip", "truncate", "extend", "duplicate", "zero",
            "insert", "erase", "boundary", "shuffle", "length"};
}

int generate_corpus(const std::filesystem::path& seed_file,
                    const std::filesystem::path& output_dir,
                    std::uint64_t count,
                    MutationKind kind,
                    std::uint64_t seed,
                    std::size_t max_size) {
    if (count == 0 || count > 100'000) {
        std::cerr << "--count must be between 1 and 100000.\n";
        return 2;
    }
    if (max_size == 0 || max_size > kAbsoluteMaxCaseBytes) {
        std::cerr << "--max-size must be between 1 and 1048576 bytes.\n";
        return 2;
    }

    std::error_code size_error;
    const auto seed_bytes = std::filesystem::file_size(seed_file, size_error);
    if (size_error || seed_bytes == 0 || seed_bytes > max_size) {
        std::cerr << "Seed must contain 1..--max-size bytes.\n";
        return 2;
    }
    std::ifstream in(seed_file, std::ios::binary);
    if (!in) {
        std::cerr << "Cannot open seed: " << seed_file << '\n';
        return 2;
    }
    std::vector<std::uint8_t> original((std::istreambuf_iterator<char>(in)), {});
    if (original.size() != seed_bytes) {
        std::cerr << "Seed read was incomplete.\n";
        return 2;
    }
    if (kind == MutationKind::DeclaredLength &&
        (original.size() < 5 || original[0] != 0x52 || original[1] != 0x46 || original[2] != 1)) {
        std::cerr << "The length mutation requires an RFSEC sample frame (magic 'RF', version 1).\n";
        return 2;
    }

    std::error_code ec;
    std::filesystem::create_directories(output_dir, ec);
    if (ec) {
        std::cerr << "Cannot create output directory: " << ec.message() << '\n';
        return 2;
    }

    std::mt19937_64 rng(seed);
    const auto manifest_path = output_dir / "manifest.csv";
    std::ofstream manifest(manifest_path, std::ios::trunc);
    if (!manifest) {
        std::cerr << "Cannot write manifest: " << manifest_path << '\n';
        return 4;
    }
    manifest << "file,size,seed,mutation\n";

    std::uint64_t total_bytes = 0;
    for (std::uint64_t i = 0; i < count; ++i) {
        auto sample = original;
        const auto actual_kind = mutate(sample, kind, rng, max_size);
        if (sample.size() > kAbsoluteMaxCorpusBytes - total_bytes) {
            std::cerr << "Corpus would exceed the 512 MiB safety limit; reduce --count or --max-size.\n";
            return 2;
        }
        std::ostringstream filename;
        filename << "case_" << std::setw(6) << std::setfill('0') << i << ".bin";
        const auto out_path = output_dir / filename.str();
        if (!write_binary(out_path, sample)) {
            std::cerr << "Could not write " << out_path << '\n';
            return 4;
        }
        total_bytes += sample.size();
        manifest << filename.str() << ',' << sample.size() << ',' << seed << ','
                 << mutation_name(actual_kind) << '\n';
    }

    std::cout << "Corpus generated (offline only)\n"
              << "  Cases:       " << count << '\n'
              << "  Total bytes: " << total_bytes << '\n'
              << "  Max case:    " << max_size << '\n'
              << "  PRNG seed:   " << seed << " (repeatable)\n"
              << "  Manifest:    " << manifest_path << '\n';
    return 0;
}

} // namespace rfsec
