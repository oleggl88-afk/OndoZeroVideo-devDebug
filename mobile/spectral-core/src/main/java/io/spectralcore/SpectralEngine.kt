package io.spectralcore

/**
 * Interface that each app's NativeLib must implement.
 * Allows SpectralIdStore (and other library classes) to call the JNI engine
 * without knowing the app-specific JNI class name/package.
 *
 * Each app compiles spectral_engine.cpp + merkle_tree.cpp from
 * spectral-core/src/main/cpp/ into its own native .so and exposes
 * these two functions via its NativeLib : SpectralEngine.
 */
interface SpectralEngine {
    /**
     * Compatibility/native bridge entrypoint implemented by each app-specific JNI layer.
     * Production code should prefer GSH_R_P_generateSpectralId().
     */
    fun generateSpectralId(seed: ByteArray): String

    /**
     * Canonical production API for GSH generation.
     * Kept as a dedicated name so all apps can target the exact-path surface
     * without forcing a JNI ABI rename in every NativeLib.
     */
    fun GSH_R_P_generateSpectralId(seed: ByteArray): String = generateSpectralId(seed)

    /**
     * Compatibility/native bridge entrypoint implemented by each app-specific JNI layer.
     * Production code should prefer GSH_R_P_computeSpectralProofP().
     *
     * Computes the Spectral Proof Seed (Patent §[0019] — Proof Generation Phase).
     * θ_temp[i] = (θ[i] + R[i]) mod range; returns the spectral invariant (32 bytes).
     * @param thetaSeed  32-byte θ seed from SpectralIdStore.getTheta()
     * @param challenge  32-byte challenge R from the smart contract
     */
    fun computeSpectralProofSeed(thetaSeed: ByteArray, challenge: ByteArray): ByteArray

    /**
     * Canonical production API for exact-path proof P computation.
     * Kept separate from computeSpectralProofSeed() so app code can standardize
     * on the GSH_R_P naming while JNI implementations stay source-compatible.
     */
    fun GSH_R_P_computeSpectralProofP(thetaSeed: ByteArray, challenge: ByteArray): ByteArray =
        computeSpectralProofSeed(thetaSeed, challenge)
}
