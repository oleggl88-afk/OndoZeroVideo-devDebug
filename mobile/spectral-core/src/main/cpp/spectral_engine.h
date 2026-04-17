#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <vector>

class SpectralEngine {
public:
    SpectralEngine(const double* theta, int n);
    ~SpectralEngine() = default;

    // Compute GSH-256 for a frame buffer (Y plane or full bytes).
    std::string process_frame(const uint8_t* data, int len);

    // Test-only alias for the future exact-path benchmark flow.
    // Keeps GSH + R + P migration work explicit without changing production call sites.
    std::string GSH_R_P_process_frame(const uint8_t* data, int len) {
        return process_frame(data, len);
    }

    // Spectral Challenge-Response: apply phase modulation θ_temp[i] = (θ[i] + R[i]) mod range,
    // then compute and return the 32-byte spectral invariant of the shifted matrix.
    // This implements θ_temp = θ + R (mod 2π) from the patent ZKP protocol.
    std::array<uint8_t, 32> compute_spectral_proof_seed(const uint8_t* challenge, int challenge_len) const;

    // Test-only alias for the future exact-path proof P benchmark.
    // Today it intentionally delegates to compute_spectral_proof_seed until the
    // final proof P definition is frozen.
    std::array<uint8_t, 32> GSH_R_P_compute_spectral_proof_p(
        const uint8_t* challenge,
        int challenge_len
    ) const {
        return compute_spectral_proof_seed(challenge, challenge_len);
    }

    // Validate spectrum invariant: sum(received_spectrum) vs trace(H(theta, frame)).
    bool verify_invariant(const double* received_spectrum, int spectrum_len, const uint8_t* data, int len);

    // Merkle support: add leaf and compute root every block.
    void add_leaf(const std::string& hex_hash);
    std::string flush_root();

private:
    int N;
    std::vector<double> theta_vec;
    std::vector<std::string> leaves;
    int frames_per_block = 1; // one frame per second per requirements

    std::string compute_hash_from_stats(double mean_gap, double std_gap, double energy) const;
};
