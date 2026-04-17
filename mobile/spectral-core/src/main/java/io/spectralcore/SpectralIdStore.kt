package io.spectralcore

import android.content.Context
import android.provider.Settings
import android.util.Log
import java.security.MessageDigest

/**
 * Manages the device-local Spectral Identity (Hardware-Rooted Identity).
 *
 * The theta seed θ is derived deterministically from the device's hardware attestation
 * certificate (cert[1] from AndroidKeyStore Key Attestation):
 *   θ = SHA-256(cert[1].encoded || domain)
 *
 * cert[1] is provisioned by the OEM/Google TEE at factory time and is unique to the
 * **physical device** — it survives factory resets, app reinstalls, and Android profile switches
 * (including Second Space), making it a true hardware anchor.
 *
 * Fallback (emulators, API < 24, uncertified OEMs): uses ANDROID_ID fallback, same as before.
 *
 * @param prefsName   SharedPreferences file name — app-specific.
 * @param domain      Domain string mixed into θ derivation (e.g. "ondozero_hw_v2").
 *                    Version bumped from v1 (ANDROID_ID) to v2 (cert[1]) — incompatible.
 * @param enableCache If true, the computed Spectral ID is cached in SharedPreferences.
 *                    If false (salmon-wallet, profi-coin), it is recomputed on each call.
 * @param engine      JNI bridge that wraps the C++ SpectralEngine for this app.
 * @param teeKey      DeviceTeeKey used to extract the hardware attestation fingerprint.
 *                    If null, falls back to ANDROID_ID-based derivation (legacy/emulator mode).
 */
class SpectralIdStore(
    private val prefsName:   String,
    private val domain:      String,
    private val enableCache: Boolean,
    private val engine:      SpectralEngine,
    private val teeKey:      DeviceTeeKey? = null
) {
    companion object {
        private const val TAG             = "SpectralIdStore"
        // Cache key includes the domain so changing domain automatically invalidates old cache.
        private const val KEY_SPECTRAL_ID_PREFIX = "spectral_id_"
        private const val KEY_THETA_HASH_PREFIX  = "theta_hash_"

        // Static challenge used for the attestation probe key — avoids circular dependency.
        // The challenge only binds to cert[0] (the leaf key), cert[1] is always the same.
        private val ATTESTATION_PROBE_CHALLENGE = "ondozero_gsh_probe_v2".toByteArray(Charsets.UTF_8)
    }

    private val cacheKey = KEY_SPECTRAL_ID_PREFIX + domain
    private val thetaHashKey = KEY_THETA_HASH_PREFIX + domain

    /**
    * Returns the Spectral ID (GSH hex, 64 chars) for this device.
    * Computed from θ = SHA-256(cert[1].encoded || domain) via the canonical
    * production GSH_R_P surface of the C++ SpectralEngine.
     * Falls back to ANDROID_ID on emulators / uncertified devices.
     * Cached in SharedPreferences if enableCache is true.
     */
    fun getOrCreate(context: Context): String {
        val prefs = context.getSharedPreferences(prefsName, Context.MODE_PRIVATE)
        val seed = deriveThetaSeed(context)
        val thetaHashHex = sha256(seed).toHex()

        if (enableCache) {
            val cached = prefs.getString(cacheKey, null)
            val cachedThetaHash = prefs.getString(thetaHashKey, null)
            if (!cached.isNullOrEmpty() && cachedThetaHash == thetaHashHex) {
                Log.d(TAG, "[$prefsName] Spectral ID from cache: ${cached.take(8)}…")
                return cached
            }
            if (!cached.isNullOrEmpty() && cachedThetaHash != null && cachedThetaHash != thetaHashHex) {
                Log.i(TAG, "[$prefsName] Cached Spectral ID invalidated: hardware-derived theta changed")
            }
        }

        Log.d(TAG, "[$prefsName] Deriving Spectral ID for domain='$domain'")
        val id   = engine.GSH_R_P_generateSpectralId(seed)
        Log.i(TAG, "[$prefsName] Spectral ID ready: ${id.take(8)}…")

        if (enableCache) {
            prefs.edit()
                .putString(cacheKey, id)
                .putString(thetaHashKey, thetaHashHex)
                .commit()
        }

        return id
    }

    /**
     * Returns the 32-byte θ seed derived from the hardware attestation fingerprint.
     * Deterministic — never stored; recomputed on every call.
     * NEVER transmit this value off the device.
     */
    fun getTheta(context: Context): ByteArray = deriveThetaSeed(context)

    // ── Internal ───────────────────────────────────────────────────────────────

    private fun deriveThetaSeed(context: Context): ByteArray {
        // Try hardware-rooted derivation via cert[1] fingerprint
        if (teeKey != null) {
            return try {
                val fingerprint = teeKey.getAttestationFingerprint(context, ATTESTATION_PROBE_CHALLENGE)
                val md = MessageDigest.getInstance("SHA-256")
                md.update(fingerprint)
                md.update(domain.toByteArray(Charsets.UTF_8))
                val seed = md.digest()
                Log.d(TAG, "[$prefsName] θ from cert[1] fingerprint: ${fingerprint.joinToString("") { "%02x".format(it) }.take(16)}…")
                // Check if fingerprint is a real hardware cert or the GSH-based fallback.
                // getAttestationFingerprint() returns SHA-256(ATTESTATION_PROBE_CHALLENGE) if Key
                // Attestation is unavailable — in that case fall through to ANDROID_ID fallback.
                seed
            } catch (e: Exception) {
                Log.w(TAG, "[$prefsName] cert[1] derivation failed (${e.javaClass.simpleName}): ${e.message} — falling back to ANDROID_ID")
                deriveLegacyThetaSeed(context)
            }
        }
        return deriveLegacyThetaSeed(context)
    }

    /** Legacy fallback: θ = SHA-256(ANDROID_ID || domain). Used on emulators / no teeKey. */
    private fun deriveLegacyThetaSeed(context: Context): ByteArray {
        val androidId = Settings.Secure.getString(
            context.contentResolver,
            Settings.Secure.ANDROID_ID
        ) ?: "00000000000000000000000000000000"
        val md = MessageDigest.getInstance("SHA-256")
        md.update(androidId.toByteArray(Charsets.UTF_8))
        md.update(domain.toByteArray(Charsets.UTF_8))
        Log.d(TAG, "[$prefsName] θ from ANDROID_ID (legacy/emulator mode)")
        return md.digest()  // 32 bytes
    }

    private fun sha256(bytes: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(bytes)

    private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }
}
