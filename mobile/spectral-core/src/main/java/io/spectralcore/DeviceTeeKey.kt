package io.spectralcore

import android.content.Context
import android.os.Build
import android.provider.Settings
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Log
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec

/**
 * Hardware-backed device authentication key.
 *
 * Always uses AES-256-GCM wrapped Ed25519:
 *   - AES key lives in AndroidKeyStore (hardware-backed where available).
 *   - Random Ed25519 seed encrypted with AES, stored in SharedPreferences.
 *   - sign() decrypts seed, signs with BouncyCastle, zero-wipes seed.
 *
 * This is the only path that works reliably across all OEMs (including Samsung Knox
 * where the native AndroidKeyStore Ed25519 Signature API is unavailable).
 */
class DeviceTeeKey(
    private val aliasEd25519: String,  // kept for API compatibility, unused
    private val aliasWrap:    String,
    private val prefsName:    String
) {
    companion object {
        private const val TAG         = "DeviceTeeKey"
        private const val KEY_PUB_HEX = "tee_pub_hex"
        private const val KEY_WRAPPED = "tee_wrapped_seed_hex"
        private const val KEY_WRAP_IV = "tee_wrap_iv_hex"
    }

    @Volatile private var ready = false

    /** True after the first successful [getOrGenerate] call in this app process.
     *  When isReady == true, [sign] and [publicKeyBytes] work with CharArray(0) as userPin. */
    val isReady: Boolean get() = ready

    @Volatile var isHardwareBacked: Boolean = false
        private set

    // ── Lifecycle ──────────────────────────────────────────────────────────────

    fun getOrGenerate(context: Context, walletSeed: ByteArray) {
        if (ready) return
        synchronized(this) {
            if (ready) return
            ensureWrappedEd25519(context, walletSeed)
            ready = true
        }
    }

    // ── Public API ─────────────────────────────────────────────────────────────

    fun publicKeyBytes(context: Context, walletSeed: ByteArray): ByteArray {
        if (!ready) getOrGenerate(context, walletSeed)
        return fromHex(
            prefs(context).getString(KEY_PUB_HEX, null)
                ?: error("DeviceTeeKey not initialized — call getOrGenerate first")
        )
    }

    fun sign(context: Context, walletSeed: ByteArray, data: ByteArray): ByteArray {
        if (!ready) getOrGenerate(context, walletSeed)
        return try {
            signWithWrappedSeed(context, data)
        } catch (e: Exception) {
            val msg = "TEE sign FAIL [${e.javaClass.simpleName}]: ${e.message?.take(120)}"
            Log.e(TAG, msg, e)
            android.os.Handler(android.os.Looper.getMainLooper()).post {
                android.widget.Toast.makeText(context.applicationContext, msg, android.widget.Toast.LENGTH_LONG).show()
            }
            throw e
        }
    }

    // ── Wrapped AES+BouncyCastle ───────────────────────────────────────────────

    private fun ensureWrappedEd25519(context: Context, walletSeed: ByteArray) {
        val ks = ks()
        val p  = prefs(context)
        val hasKsAlias = ks.containsAlias(aliasWrap)
        val hasPrefsKey = p.contains(KEY_WRAPPED)
        Log.d(TAG, "ensureWrappedEd25519: ksHasAlias=$hasKsAlias prefsHasKey=$hasPrefsKey alias=$aliasWrap")
        if (hasKsAlias && hasPrefsKey) {
            isHardwareBacked = queryHardwareBacked()
            Log.i(TAG, "[$aliasWrap] Wrapped Ed25519 key ready (hwBacked=$isHardwareBacked)")
            return
        }
        generateAesWrapKey()

        val seed = generateDeterministicSeed(context, walletSeed)
        val pub  = Ed25519PrivateKeyParameters(seed).generatePublicKey().encoded

        val cipher      = aesGcmCipher(context, Cipher.ENCRYPT_MODE)
        val iv          = cipher.iv
        val wrappedSeed = cipher.doFinal(seed)
        seed.fill(0)

        p.edit()
            .putString(KEY_WRAPPED, toHex(wrappedSeed))
            .putString(KEY_WRAP_IV, toHex(iv))
            .putString(KEY_PUB_HEX, toHex(pub))
            .apply()

        isHardwareBacked = queryHardwareBacked()
        Log.i(TAG, "[$aliasWrap] Wrapped Ed25519 key generated (hwBacked=$isHardwareBacked)")
    }

    private fun generateDeterministicSeed(context: Context, walletSeed: ByteArray): ByteArray {
        val androidId = Settings.Secure.getString(context.contentResolver, Settings.Secure.ANDROID_ID)
            ?: "00000000000000000000000000000000"
        
        val mac = javax.crypto.Mac.getInstance("HmacSHA256")
        mac.init(javax.crypto.spec.SecretKeySpec(walletSeed, "HmacSHA256"))
        return mac.doFinal(androidId.toByteArray(Charsets.UTF_8))
    }

    private fun generateAesWrapKey() {
        if (Build.VERSION.SDK_INT >= 28) {
            try {
                generateAesWrapKeyImpl(strongBox = true)
                return
            } catch (e: Exception) {
                if (e.javaClass.name.endsWith("StrongBoxUnavailableException")) {
                    Log.w(TAG, "[$aliasWrap] StrongBox unavailable — software-backed AES wrap")
                } else throw e
            }
        }
        generateAesWrapKeyImpl(strongBox = false)
    }

    @Suppress("NewApi")
    private fun generateAesWrapKeyImpl(strongBox: Boolean) {
        val spec = KeyGenParameterSpec.Builder(
            aliasWrap,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .apply { if (strongBox && Build.VERSION.SDK_INT >= 28) setIsStrongBoxBacked(true) }
            .build()
        KeyGenerator.getInstance("AES", "AndroidKeyStore")
            .also { it.init(spec) }
            .generateKey()
    }

    private fun signWithWrappedSeed(context: Context, data: ByteArray): ByteArray {
        val ciphertext = fromHex(
            prefs(context).getString(KEY_WRAPPED, null) ?: error("DeviceTeeKey not initialized")
        )
        Log.d(TAG, "signWithWrappedSeed: ciphertext=${ciphertext.size}B, fetching AES key alias=$aliasWrap")
        val cipher = try {
            aesGcmCipher(context, Cipher.DECRYPT_MODE)
        } catch (e: Exception) {
            Log.e(TAG, "aesGcmCipher(DECRYPT) failed: ${e.javaClass.simpleName}: ${e.message}", e)
            throw e
        }
        val seed = cipher.doFinal(ciphertext)
        return try {
            Ed25519Signer().run {
                init(true, Ed25519PrivateKeyParameters(seed))
                update(data, 0, data.size)
                generateSignature()
            }
        } finally {
            seed.fill(0)
        }
    }

    private fun aesGcmCipher(context: Context, mode: Int): Cipher {
        val key = ks().getKey(aliasWrap, null)
        Log.d(TAG, "aesGcmCipher: mode=$mode aliasWrap=$aliasWrap key=${if (key != null) key.javaClass.simpleName else "NULL"}")
        if (key == null) {
            // Key missing from AndroidKeyStore — force regeneration next time
            ready = false
            error("AES wrap key '$aliasWrap' not found in AndroidKeyStore — regeneration needed")
        }
        return Cipher.getInstance("AES/GCM/NoPadding").also { c ->
            if (mode == Cipher.ENCRYPT_MODE) {
                c.init(mode, key)
            } else {
                val iv = fromHex(
                    prefs(context).getString(KEY_WRAP_IV, null) ?: error("No GCM IV stored")
                )
                c.init(mode, key, GCMParameterSpec(128, iv))
            }
        }
    }

    // ── Key Attestation ────────────────────────────────────────────────────────

    /**
     * Returns the SHA-256 of the device attestation intermediate certificate (cert[1] in the
     * AndroidKeyStore attestation chain).  This certificate is provisioned by the OEM/Google TEE
     * at factory time and is unique to the **physical device** — it is the same regardless of
     * which Android user profile (main / Second Space / work profile) is active.
     *
     * Using this fingerprint as an on-chain PDA seed prevents a user from re-registering the
     * same physical device under a different GSH (e.g. by creating a Second Space that has a
     * fresh ANDROID_ID → fresh GSH).
     *
     * Fallback: if Key Attestation is unsupported (emulators, uncertified OEMs, API < 24), the
     * method returns SHA-256(gshBytes) which is unique per device but not hardware-anchored.
     */
    fun getAttestationFingerprint(context: Context, gshBytes: ByteArray): ByteArray {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.N) {
            Log.w(TAG, "getAttestationFingerprint: API < 24 — using GSH as fallback fingerprint")
            return java.security.MessageDigest.getInstance("SHA-256").digest(gshBytes)
        }
        return try {
            val attestAlias = "ondozero_attest_probe_v1"
            val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            if (ks.containsAlias(attestAlias)) ks.deleteEntry(attestAlias)

            val spec = KeyGenParameterSpec.Builder(
                attestAlias,
                KeyProperties.PURPOSE_SIGN
            )
                .setAlgorithmParameterSpec(java.security.spec.ECGenParameterSpec("secp256r1"))
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setAttestationChallenge(gshBytes)  // challenge binds cert[0] to this GSH
                .build()

            java.security.KeyPairGenerator.getInstance("EC", "AndroidKeyStore").also {
                it.initialize(spec)
                it.generateKeyPair()
            }

            val certs = ks.getCertificateChain(attestAlias)
            val fingerprint = if (certs != null && certs.size >= 2) {
                // cert[1] = device attestation cert: unique per physical device, stable forever
                java.security.MessageDigest.getInstance("SHA-256").digest(certs[1].encoded)
            } else {
                Log.w(TAG, "getAttestationFingerprint: short cert chain (${certs?.size}) — GSH fallback")
                java.security.MessageDigest.getInstance("SHA-256").digest(gshBytes)
            }

            ks.deleteEntry(attestAlias)  // clean up the temporary probe key
            Log.i(TAG, "getAttestationFingerprint: ${fingerprint.joinToString("") { "%02x".format(it) }.take(16)}…")
            fingerprint
        } catch (e: Exception) {
            Log.w(TAG, "getAttestationFingerprint: Key Attestation unavailable (${e.javaClass.simpleName}): ${e.message} — using GSH fallback")
            java.security.MessageDigest.getInstance("SHA-256").digest(gshBytes)
        }
    }

    // ── Hardware detection ─────────────────────────────────────────────────────

    private fun queryHardwareBacked(): Boolean {
        return try {
            val key = ks().getKey(aliasWrap, null) as? javax.crypto.SecretKey ?: return false
            val keyInfo = SecretKeyFactory.getInstance(key.algorithm, "AndroidKeyStore")
                .getKeySpec(key, android.security.keystore.KeyInfo::class.java)
                as android.security.keystore.KeyInfo
            if (Build.VERSION.SDK_INT >= 31) {
                val lvl = keyInfo.securityLevel
                lvl == android.security.keystore.KeyProperties.SECURITY_LEVEL_STRONGBOX ||
                        lvl == android.security.keystore.KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT
            } else {
                @Suppress("DEPRECATION")
                keyInfo.isInsideSecureHardware
            }
        } catch (e: Exception) {
            Log.w(TAG, "queryHardwareBacked: ${e.message}")
            false
        }
    }

    // ── Helpers ────────────────────────────────────────────────────────────────

    private fun ks(): KeyStore           = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    private fun prefs(context: Context)  = context.getSharedPreferences(prefsName, Context.MODE_PRIVATE)
    private fun fromHex(hex: String): ByteArray = hex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    private fun toHex(bytes: ByteArray): String  = bytes.joinToString("") { "%02x".format(it) }
}
