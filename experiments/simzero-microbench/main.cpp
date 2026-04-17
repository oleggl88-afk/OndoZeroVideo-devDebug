#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <random>
#include <sstream>
#include <string>
#include <vector>

#include <Eigen/Dense>
#include <Eigen/Eigenvalues>

using Eigen::EigenSolver;
using Eigen::MatrixXd;
using Eigen::VectorXd;
using std::chrono::duration_cast;
using std::chrono::high_resolution_clock;
using std::chrono::milliseconds;

namespace {

constexpr double kPhaseShift = M_PI / 6.0; // avoids degenerate sin/cos
constexpr uint64_t kFnvOffset = 1469598103934665603ULL;
constexpr uint64_t kFnvPrime = 1099511628211ULL;

struct Scenario {
    int hash_bits;
    int matrix_dim;
    int key_bits;
};

struct Stats {
    double mean_gap;
    double std_gap;
    double energy;
    uint64_t hash;
};

std::vector<double> get_primes(int n) {
    std::vector<double> primes;
    primes.reserve(n);
    int num = 2;
    while (static_cast<int>(primes.size()) < n) {
        bool is_prime = true;
        for (int d = 2; d * d <= num; ++d) {
            if (num % d == 0) {
                is_prime = false;
                break;
            }
        }
        if (is_prime) primes.push_back(static_cast<double>(num));
        ++num;
    }
    return primes;
}

// Simple FNV-1a over ASCII text.
uint64_t fnv1a(const std::string &text) {
    uint64_t hash = kFnvOffset;
    for (unsigned char c : text) {
        hash ^= static_cast<uint64_t>(c);
        hash *= kFnvPrime;
    }
    return hash;
}

class SimZeroCore {
  public:
    explicit SimZeroCore(int size) : N(size), A(MatrixXd::Zero(size, size)), p_diag(VectorXd::Zero(size)) {
        auto primes = get_primes(N);
        for (int m = 0; m < N; ++m) {
            p_diag(m) = std::pow(primes[m], 0.3);
            for (int n = 0; n < N; ++n) {
                if (m == n) continue;
                double dist = std::sqrt(std::abs(m - n));
                double kernel = std::abs(std::cos(M_PI * std::log(primes[m] / primes[n])));
                A(m, n) = (1.0 / dist) * kernel;
            }
        }
    }

    Stats stats_for_key(const std::vector<int> &binary_key) const {
        MatrixXd H = MatrixXd::Zero(N, N);
        VectorXd theta = VectorXd::Zero(N);
        for (int i = 0; i < N; ++i) {
            theta(i) = binary_key[i] ? M_PI + kPhaseShift : kPhaseShift;
        }

        VectorXd cos_t = theta.array().cos();
        VectorXd sin_t = theta.array().sin();

        for (int m = 0; m < N; ++m) {
            for (int n = 0; n < N; ++n) {
                if (m == n) {
                    H(m, n) = p_diag(m);
                } else {
                    H(m, n) = A(m, n) * (cos_t(m) + 0.5 * sin_t(n));
                }
            }
        }

        EigenSolver<MatrixXd> solver(H, /* computeEigenvectors */ false);
        VectorXd spectrum = solver.eigenvalues().real();
        std::sort(spectrum.data(), spectrum.data() + spectrum.size());

        std::vector<double> gaps;
        gaps.reserve(N - 1);
        for (int i = 1; i < N; ++i) {
            gaps.push_back(spectrum(i) - spectrum(i - 1));
        }

        double mean_gap = 0.0;
        for (double g : gaps) mean_gap += g;
        mean_gap /= static_cast<double>(gaps.size());

        double var_gap = 0.0;
        for (double g : gaps) {
            double diff = g - mean_gap;
            var_gap += diff * diff;
        }
        var_gap /= static_cast<double>(gaps.size());
        double std_gap = std::sqrt(var_gap);

        double energy = 0.0;
        for (int i = 0; i < N; ++i) energy += spectrum(i) * spectrum(i);

        std::ostringstream oss;
        oss << std::fixed << std::setprecision(10)
            << mean_gap << '|' << std_gap << '|' << energy;

        Stats stats{};
        stats.mean_gap = mean_gap;
        stats.std_gap = std_gap;
        stats.energy = energy;
        stats.hash = fnv1a(oss.str());
        return stats;
    }

    uint64_t hash_for_key(const std::vector<int> &binary_key) const {
        return stats_for_key(binary_key).hash;
    }

  private:
    int N;
    MatrixXd A;
    VectorXd p_diag;
};

std::vector<int> int_to_key(std::uint64_t value, int width) {
    std::vector<int> key(width, 0);
    for (int i = 0; i < width; ++i) {
        key[i] = static_cast<int>((value >> i) & 1ULL);
    }
    return key;
}

uint64_t mask_for_bits(int bits) {
    if (bits >= 64) return std::numeric_limits<uint64_t>::max();
    return (1ULL << bits) - 1ULL;
}

struct ResultRow {
    int hash_bits;
    int matrix_dim;
    int key_bits;
    uint64_t search_space;
    uint64_t tested;
    bool found;
    double mean_gap;
    double std_gap;
    double energy;
    double crack_ms;
};

} // namespace

int main(int argc, char **argv) {
    std::size_t max_candidates = std::numeric_limits<std::size_t>::max();
    double time_limit_sec = 6.0 * 3600.0; // default 6 hours
    const uint64_t max_landscape_samples = 2000; // cap rows per scenario

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        const std::string max_prefix = "--max-candidates=";
        const std::string time_prefix = "--time-limit-sec=";
        if (arg.rfind(max_prefix, 0) == 0) {
            max_candidates = static_cast<std::size_t>(std::stoull(arg.substr(max_prefix.size())));
        } else if (arg.rfind(time_prefix, 0) == 0) {
            time_limit_sec = std::stod(arg.substr(time_prefix.size()));
        }
    }

    std::vector<Scenario> scenarios = {
        {8, 6, 6},     // very small, instant brute-force
        {12, 8, 8},    // small, still fast
        {16, 10, 10},  // moderate
        {20, 12, 12},  // slightly larger but still laptop-friendly
        {24, 14, 14},  // extended hash/key/size
        {28, 16, 16},  // larger matrix, powers-of-two space
        {32, 18, 18},  // bigger matrix, still within laptop reach
        {36, 20, 20},  // million-scale search space
        {40, 22, 22},  // few million
        {44, 24, 24}   // ~16M, targets ~20 minutes on CPU
    };

    std::mt19937 rng(1337);
    std::uniform_int_distribution<int> bit_dist(0, 1);

    std::vector<ResultRow> results;
    results.reserve(scenarios.size());

    for (const auto &sc : scenarios) {
        SimZeroCore core(sc.matrix_dim);

        std::vector<int> secret_key(sc.matrix_dim, 0);
        for (int i = 0; i < sc.matrix_dim; ++i) {
            secret_key[i] = bit_dist(rng);
        }

        const uint64_t mask = mask_for_bits(sc.hash_bits);
        Stats target_stats = core.stats_for_key(secret_key);
        const uint64_t target = target_stats.hash & mask;
        const uint64_t search_space = 1ULL << sc.key_bits;
        const uint64_t limit = std::min<uint64_t>(search_space, max_candidates);

        const uint64_t sample_stride = std::max<uint64_t>(1, search_space / max_landscape_samples);
        std::vector<std::string> landscape_rows;
        landscape_rows.reserve(static_cast<std::size_t>(search_space / sample_stride) + 1);

        auto t0 = high_resolution_clock::now();
        uint64_t found = std::numeric_limits<uint64_t>::max();
        uint64_t tested = 0;
        bool recorded_found_row = false;

        for (uint64_t candidate = 0; candidate < limit; ++candidate) {
            std::vector<int> key = int_to_key(candidate, sc.matrix_dim);
            Stats stats = core.stats_for_key(key);
            uint64_t h = stats.hash & mask;
            ++tested;

            if (candidate % sample_stride == 0) {
                std::ostringstream row;
                row << sc.hash_bits << ',' << sc.matrix_dim << ',' << candidate << ','
                    << std::fixed << std::setprecision(10)
                    << stats.mean_gap << ',' << stats.std_gap << ',' << stats.energy << ','
                    << (h == target ? 1 : 0);
                landscape_rows.push_back(row.str());
            }

            if (h == target) {
                found = candidate;
                if (candidate % sample_stride != 0) {
                    std::ostringstream row;
                    row << sc.hash_bits << ',' << sc.matrix_dim << ',' << candidate << ','
                        << std::fixed << std::setprecision(10)
                        << stats.mean_gap << ',' << stats.std_gap << ',' << stats.energy << ',' << 1;
                    landscape_rows.push_back(row.str());
                }
                recorded_found_row = true;
                break;
            }

            auto now = high_resolution_clock::now();
            double elapsed_sec = static_cast<double>(duration_cast<milliseconds>(now - t0).count()) / 1000.0;
            if (elapsed_sec >= time_limit_sec) break;
        }
        auto t1 = high_resolution_clock::now();

        double elapsed_ms = static_cast<double>(duration_cast<milliseconds>(t1 - t0).count());
        bool solved = found != std::numeric_limits<uint64_t>::max();
        results.push_back({sc.hash_bits, sc.matrix_dim, sc.key_bits, search_space, tested, solved,
                           target_stats.mean_gap, target_stats.std_gap, target_stats.energy, elapsed_ms});

        std::cout << "Scenario hash_bits=" << sc.hash_bits << " dim=" << sc.matrix_dim
                  << " space=" << search_space << " tested=" << tested
                  << " -> " << (solved ? "found key " + std::to_string(found) : "not found")
                  << " in " << elapsed_ms << " ms" << std::endl;

        const std::string landscape_path = "landscape_" + std::to_string(sc.hash_bits) + "_" + std::to_string(sc.matrix_dim) + ".csv";
        std::ofstream lout(landscape_path, std::ios::out | std::ios::trunc);
        if (!lout) {
            std::cerr << "Failed to open " << landscape_path << " for writing" << std::endl;
        } else {
            lout << "hash_bits,matrix_dim,candidate,mean_gap,std_gap,energy,is_target" << '\n';
            for (const auto &row : landscape_rows) lout << row << '\n';
            if (!solved && !recorded_found_row) {
                std::cout << "(target not found within limits; landscape truncated)" << std::endl;
            }
            std::cout << "Landscape samples -> " << landscape_path << std::endl;
        }
    }

    const std::string csv_path = "results.csv";
    std::ofstream csv(csv_path, std::ios::out | std::ios::trunc);
    if (!csv) {
        std::cerr << "Failed to open results.csv for writing" << std::endl;
        return 1;
    }
    csv << "hash_bits,matrix_dim,key_bits,search_space,tested,found,mean_gap,std_gap,energy,crack_time_ms" << '\n';
    for (const auto &row : results) {
        csv << row.hash_bits << ',' << row.matrix_dim << ',' << row.key_bits << ',' << row.search_space << ','
            << row.tested << ',' << (row.found ? 1 : 0) << ','
            << std::fixed << std::setprecision(10)
            << row.mean_gap << ',' << row.std_gap << ',' << row.energy << ','
            << std::setprecision(3) << row.crack_ms << '\n';
    }

    std::cout << "\nCSV saved to " << csv_path << std::endl;
    return 0;
}
