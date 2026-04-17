#include "spectral_engine.h"

#include <algorithm>
#include <array>
#include <cmath>
#include <cstdint>
#include <iomanip>
#include <numeric>
#include <sstream>
#include <string>
#include <vector>

namespace {
constexpr uint64_t kSeed1 = 0x8f3f73d2ab9c4d11ULL;
constexpr uint64_t kSeed2 = 0x4c1f17a3de7b9213ULL;
constexpr uint64_t kSeed3 = 0x32b47a90efc12345ULL;
constexpr uint64_t kSeed4 = 0x1bd3765ac98e024fULL;
constexpr double kTwoPi = 6.28318530717958647692;
constexpr double kPi = 3.14159265358979323846;
constexpr double kQrEpsilon = 1e-12;
constexpr int kQrIterations = 18;

uint64_t mix(uint64_t state, uint64_t value) {
    state ^= value + 0x9e3779b97f4a7c15ULL + (state << 6) + (state >> 2);
    state = (state ^ (state >> 30)) * 0xbf58476d1ce4e5b9ULL;
    state = (state ^ (state >> 27)) * 0x94d049bb133111ebULL;
    state ^= (state >> 31);
    return state;
}

std::string to_hex(const std::array<uint8_t, 32>& bytes) {
    std::ostringstream oss;
    for (auto b : bytes) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
    }
    return oss.str();
}

std::array<uint8_t, 32> digest_from_stats(double mean, double stddev, double energy, const std::vector<double>& theta) {
    uint64_t h1 = kSeed1;
    uint64_t h2 = kSeed2;
    uint64_t h3 = kSeed3;
    uint64_t h4 = kSeed4;

    auto feed = [&](double v) {
        // Preserve sign while keeping deterministic mix.
        int64_t scaled = static_cast<int64_t>(std::llround(v * 1e6));
        uint64_t mag = static_cast<uint64_t>(std::abs(scaled));
        h1 = mix(h1, mag + 0x1234ULL);
        h2 = mix(h2, static_cast<uint64_t>(scaled >= 0 ? 0xaaaaULL : 0xbbbbULL));
        h3 = mix(h3, static_cast<uint64_t>(mag << 1) ^ 0x5a5aULL);
        h4 = mix(h4, static_cast<uint64_t>(mag >> 1) ^ 0x6b6bULL);
    };

    feed(mean);
    feed(stddev);
    feed(energy);

    // Incorporate a few theta entries to keep digest tied to current session.
    for (size_t i = 0; i < theta.size() && i < 8; ++i) {
        feed(theta[i]);
    }

    std::array<uint8_t, 32> out{};
    uint64_t seeds[4] = {h1, h2, h3, h4};
    for (int i = 0; i < 4; ++i) {
        uint64_t v = seeds[i];
        for (int b = 0; b < 8; ++b) {
            out[i * 8 + b] = static_cast<uint8_t>((v >> (8 * b)) & 0xFF);
        }
    }
    return out;
}

std::string combine_hashes(const std::string& a, const std::string& b) {
    uint64_t h = kSeed2;
    for (char c : a) h = mix(h, static_cast<uint64_t>(c));
    for (char c : b) h = mix(h, static_cast<uint64_t>(c));
    std::array<uint8_t, 32> out{};
    for (int i = 0; i < 32; ++i) {
        out[i] = static_cast<uint8_t>((h >> ((i % 8) * 8)) & 0xFF);
        h = mix(h, static_cast<uint64_t>(i * 17 + 31));
    }
    return to_hex(out);
}

double normalize_angle(double value) {
    double normalized = std::fmod(value, kTwoPi);
    if (normalized < 0.0) {
        normalized += kTwoPi;
    }
    return normalized;
}

std::vector<int> generate_primes(int count) {
    std::vector<int> primes;
    primes.reserve(count);
    int candidate = 2;
    while (static_cast<int>(primes.size()) < count) {
        bool is_prime = true;
        for (int prime : primes) {
            if (prime * prime > candidate) {
                break;
            }
            if (candidate % prime == 0) {
                is_prime = false;
                break;
            }
        }
        if (is_prime) {
            primes.push_back(candidate);
        }
        ++candidate;
    }
    return primes;
}

std::vector<double> build_shifted_theta(const std::vector<double>& theta_vec, const uint8_t* challenge, int challenge_len) {
    const int n = static_cast<int>(theta_vec.size());
    std::vector<double> theta_temp(n, 0.0);
    for (int index = 0; index < n; ++index) {
        double theta_phase = normalize_angle((theta_vec[index] + 1.0) * kPi);
        double challenge_phase = 0.0;
        if (challenge_len > 0) {
            challenge_phase = (static_cast<double>(challenge[index % challenge_len]) / 255.0) * kTwoPi;
        }
        theta_temp[index] = normalize_angle(theta_phase + challenge_phase);
    }
    return theta_temp;
}

std::vector<double> build_exact_gou_matrix(const std::vector<double>& theta_temp) {
    const int n = static_cast<int>(theta_temp.size());
    const auto primes = generate_primes(n);
    const double max_prime = static_cast<double>(primes.back());

    std::vector<double> matrix(static_cast<size_t>(n) * static_cast<size_t>(n), 0.0);
    for (int row = 0; row < n; ++row) {
        const double phase_row = theta_temp[row];
        const double prime_row = static_cast<double>(primes[row]) / max_prime;
        for (int col = 0; col < n; ++col) {
            const double phase_col = theta_temp[col];
            const double prime_col = static_cast<double>(primes[col]) / max_prime;
            const double asymmetric_core =
                std::cos(phase_row * (1.0 + prime_col)) +
                std::sin(phase_col * (1.0 + prime_row));
            const double coupling = 0.35 * std::cos(phase_row - phase_col);
            const double twisted = 0.20 * std::sin((prime_row * phase_row) - (prime_col * phase_col));
            const double locality = 0.10 * std::sin((static_cast<double>(row + 1) * phase_row) / static_cast<double>(n)) -
                0.10 * std::cos((static_cast<double>(col + 1) * phase_col) / static_cast<double>(n));
            matrix[static_cast<size_t>(row) * static_cast<size_t>(n) + static_cast<size_t>(col)] =
                asymmetric_core + coupling + twisted + locality;
        }
    }
    return matrix;
}

std::pair<std::vector<double>, std::vector<double>> qr_decompose(const std::vector<double>& matrix, int n) {
    std::vector<double> q(static_cast<size_t>(n) * static_cast<size_t>(n), 0.0);
    std::vector<double> r(static_cast<size_t>(n) * static_cast<size_t>(n), 0.0);
    std::vector<double> v = matrix;

    for (int column = 0; column < n; ++column) {
        double norm_sq = 0.0;
        for (int row = 0; row < n; ++row) {
            const double value = v[static_cast<size_t>(row) * static_cast<size_t>(n) + static_cast<size_t>(column)];
            norm_sq += value * value;
        }
        const double norm = std::sqrt(std::max(norm_sq, kQrEpsilon));
        r[static_cast<size_t>(column) * static_cast<size_t>(n) + static_cast<size_t>(column)] = norm;

        for (int row = 0; row < n; ++row) {
            q[static_cast<size_t>(row) * static_cast<size_t>(n) + static_cast<size_t>(column)] =
                v[static_cast<size_t>(row) * static_cast<size_t>(n) + static_cast<size_t>(column)] / norm;
        }

        for (int next = column + 1; next < n; ++next) {
            double projection = 0.0;
            for (int row = 0; row < n; ++row) {
                projection +=
                    q[static_cast<size_t>(row) * static_cast<size_t>(n) + static_cast<size_t>(column)] *
                    v[static_cast<size_t>(row) * static_cast<size_t>(n) + static_cast<size_t>(next)];
            }
            r[static_cast<size_t>(column) * static_cast<size_t>(n) + static_cast<size_t>(next)] = projection;
            for (int row = 0; row < n; ++row) {
                v[static_cast<size_t>(row) * static_cast<size_t>(n) + static_cast<size_t>(next)] -=
                    q[static_cast<size_t>(row) * static_cast<size_t>(n) + static_cast<size_t>(column)] * projection;
            }
        }
    }

    return {q, r};
}

std::vector<double> multiply_square(const std::vector<double>& left, const std::vector<double>& right, int n) {
    std::vector<double> out(static_cast<size_t>(n) * static_cast<size_t>(n), 0.0);
    for (int row = 0; row < n; ++row) {
        for (int pivot = 0; pivot < n; ++pivot) {
            const double lhs = left[static_cast<size_t>(row) * static_cast<size_t>(n) + static_cast<size_t>(pivot)];
            if (std::abs(lhs) <= kQrEpsilon) {
                continue;
            }
            for (int col = 0; col < n; ++col) {
                out[static_cast<size_t>(row) * static_cast<size_t>(n) + static_cast<size_t>(col)] +=
                    lhs * right[static_cast<size_t>(pivot) * static_cast<size_t>(n) + static_cast<size_t>(col)];
            }
        }
    }
    return out;
}

std::vector<double> approximate_real_spectrum(std::vector<double> matrix, int n) {
    for (int iteration = 0; iteration < kQrIterations; ++iteration) {
        auto [q, r] = qr_decompose(matrix, n);
        matrix = multiply_square(r, q, n);
    }

    std::vector<double> diagonal(n, 0.0);
    for (int index = 0; index < n; ++index) {
        diagonal[index] = matrix[static_cast<size_t>(index) * static_cast<size_t>(n) + static_cast<size_t>(index)];
    }
    return diagonal;
}

std::array<uint8_t, 32> digest_from_interval_spectrum(const std::vector<double>& spectrum) {
    std::vector<double> sorted = spectrum;
    std::sort(sorted.begin(), sorted.end());

    const double min_value = sorted.front();
    const double max_value = sorted.back();
    const double span = std::max(max_value - min_value, 1e-9);

    std::array<uint8_t, 32> bucket_bytes{};
    const size_t bucket_count = bucket_bytes.size();
    for (size_t bucket = 0; bucket < bucket_count; ++bucket) {
        const size_t begin = (bucket * sorted.size()) / bucket_count;
        const size_t end = std::max(begin + 1, ((bucket + 1) * sorted.size()) / bucket_count);
        double sum = 0.0;
        for (size_t index = begin; index < end; ++index) {
            sum += sorted[index];
        }
        const double average = sum / static_cast<double>(end - begin);
        const double normalized = std::clamp((average - min_value) / span, 0.0, 1.0);
        bucket_bytes[bucket] = static_cast<uint8_t>(std::lround(normalized * 255.0));
    }

    uint64_t h1 = kSeed1;
    uint64_t h2 = kSeed2;
    uint64_t h3 = kSeed3;
    uint64_t h4 = kSeed4;
    for (size_t index = 0; index < bucket_count; ++index) {
        const uint64_t value = static_cast<uint64_t>(bucket_bytes[index]);
        h1 = mix(h1, value + static_cast<uint64_t>(index * 17 + 1));
        h2 = mix(h2, (value << 1) ^ static_cast<uint64_t>(index * 19 + 3));
        h3 = mix(h3, (value << 8) ^ static_cast<uint64_t>(index * 23 + 5));
        h4 = mix(h4, (value << 16) ^ static_cast<uint64_t>(index * 29 + 7));
    }

    std::array<uint8_t, 32> out{};
    const uint64_t seeds[4] = {h1, h2, h3, h4};
    for (int seed_index = 0; seed_index < 4; ++seed_index) {
        uint64_t value = seeds[seed_index];
        for (int byte_index = 0; byte_index < 8; ++byte_index) {
            out[seed_index * 8 + byte_index] = static_cast<uint8_t>((value >> (8 * byte_index)) & 0xFF);
        }
    }
    return out;
}
}

SpectralEngine::SpectralEngine(const double* theta, int n) : N(n), theta_vec(theta, theta + n) {}

std::string SpectralEngine::compute_hash_from_stats(double mean_gap, double std_gap, double energy) const {
    auto digest = digest_from_stats(mean_gap, std_gap, energy, theta_vec);
    return to_hex(digest);
}

std::string SpectralEngine::process_frame(const uint8_t* data, int len) {
    if (len <= 0 || data == nullptr) return "";

    double sum = 0.0;
    double energy = 0.0;
    for (int i = 0; i < len; ++i) {
        double v = static_cast<uint8_t>(data[i]);
        sum += v;
        energy += v * v;
    }
    double mean = sum / static_cast<double>(len);

    double var = 0.0;
    for (int i = 0; i < len; ++i) {
        double v = static_cast<uint8_t>(data[i]);
        double diff = v - mean;
        var += diff * diff;
    }
    var /= static_cast<double>(std::max(len - 1, 1));
    double stddev = std::sqrt(var);

    auto gsh_hex = compute_hash_from_stats(mean, stddev, energy);
    add_leaf(gsh_hex);
    return gsh_hex;
}

std::array<uint8_t, 32> SpectralEngine::compute_spectral_proof_seed(
        const uint8_t* challenge, int challenge_len) const {
    // Test-oriented exact-path approximation for GSH + R + P benchmarking.
    // 1. Convert theta to phase angles on [0, 2π).
    // 2. Shift by on-chain challenge R.
    // 3. Build a non-symmetric interaction matrix using phase kernels and prime weights.
    // 4. Run iterative QR decomposition to approximate the real spectrum.
    // 5. Hash interval summaries of the spectrum into a 32-byte proof P.

    const auto theta_temp = build_shifted_theta(theta_vec, challenge, challenge_len);
    const auto matrix = build_exact_gou_matrix(theta_temp);
    const auto spectrum = approximate_real_spectrum(matrix, static_cast<int>(theta_temp.size()));
    return digest_from_interval_spectrum(spectrum);
}

bool SpectralEngine::verify_invariant(const double* received_spectrum, int spectrum_len, const uint8_t* data, int len) {
    if (received_spectrum == nullptr || spectrum_len <= 0) return false;
    double expected = 0.0;
    for (double t : theta_vec) expected += std::abs(t);
    double sum_recv = 0.0;
    for (int i = 0; i < spectrum_len; ++i) sum_recv += received_spectrum[i];
    // Soft tolerance to allow numeric noise.
    return std::abs(sum_recv - expected) < 1e-3;
}

void SpectralEngine::add_leaf(const std::string& hex_hash) {
    leaves.push_back(hex_hash);
    if (static_cast<int>(leaves.size()) >= frames_per_block) {
        // no-op; flush_root performs reduction and reset.
    }
}

std::string SpectralEngine::flush_root() {
    if (leaves.empty()) return "";
    std::vector<std::string> level = leaves;
    while (level.size() > 1) {
        if (level.size() % 2 != 0) level.push_back(level.back());
        std::vector<std::string> next;
        next.reserve(level.size() / 2);
        for (size_t i = 0; i < level.size(); i += 2) {
            next.push_back(combine_hashes(level[i], level[i + 1]));
        }
        level = std::move(next);
    }
    std::string root = level.front();
    leaves.clear();
    return root;
}
