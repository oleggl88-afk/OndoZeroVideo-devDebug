package io.spectralcore

import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Log
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import java.nio.charset.StandardCharsets
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

class AppPinAuthManager(private val context: Context) {

    companion object {
        private const val TAG = "AppPinAuthManager"
        private const val KEY_ALIAS = "ondozero_pin_key_v1"
        private const val PREFS_NAME = "ondozero_pin_prefs"
        private const val PREF_ENCRYPTED_PIN = "encrypted_pin"
        private const val PREF_IV = "pin_iv"
    }

    private val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
    private val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    fun hasSavedPin(): Boolean {
        return (prefs.contains(PREF_ENCRYPTED_PIN) && prefs.contains(PREF_IV)) || prefs.contains("pin_plain")
    }

    fun savePinPlaintext(pin: CharArray) {
        prefs.edit().putString("pin_plain", String(pin)).apply()
    }

    fun getPinPlaintext(): CharArray? {
        return prefs.getString("pin_plain", null)?.toCharArray()
    }

    fun isBiometricAvailable(): Boolean {
        val biometricManager = BiometricManager.from(context)
        val authType = BiometricManager.Authenticators.BIOMETRIC_STRONG or BiometricManager.Authenticators.DEVICE_CREDENTIAL
        return biometricManager.canAuthenticate(authType) == BiometricManager.BIOMETRIC_SUCCESS
    }

    private fun getOrCreateKey(): SecretKey {
        if (!ks.containsAlias(KEY_ALIAS)) {
            val builder = KeyGenParameterSpec.Builder(
                KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
             .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
             .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
             .setUserAuthenticationRequired(true)
             
            if (Build.VERSION.SDK_INT >= 30) {
                 builder.setUserAuthenticationParameters(
                     0, // Require auth for every use
                     KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL
                 )
            } else {
                 @Suppress("DEPRECATION")
                 builder.setUserAuthenticationValidityDurationSeconds(-1)
            }

            KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
                .apply { init(builder.build()) }
                .generateKey()
        }
        return ks.getKey(KEY_ALIAS, null) as SecretKey
    }

    fun savePinWithBiometrics(pin: CharArray, activity: FragmentActivity, onResult: (Boolean, Exception?) -> Unit) {
        try {
            val key = getOrCreateKey()
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, key)

            val promptInfo = BiometricPrompt.PromptInfo.Builder()
                .setTitle("Secure your PIN")
                .setSubtitle("Save your PIN using biometrics")
                .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG or BiometricManager.Authenticators.DEVICE_CREDENTIAL)
                .build()

            val cryptoObject = BiometricPrompt.CryptoObject(cipher)

            val biometricPrompt = BiometricPrompt(activity, ContextCompat.getMainExecutor(activity),
                object : BiometricPrompt.AuthenticationCallback() {
                    override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                        onResult(false, Exception("Auth error: $errString"))
                    }

                    override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                        try {
                            val authCipher = result.cryptoObject?.cipher ?: throw Exception("Cipher is null")
                            val pinBytes = String(pin).toByteArray(StandardCharsets.UTF_8)
                            val encrypted = authCipher.doFinal(pinBytes)
                            val iv = authCipher.iv
                            pinBytes.fill(0) // Wipe

                            prefs.edit()
                                .putString(PREF_ENCRYPTED_PIN, android.util.Base64.encodeToString(encrypted, android.util.Base64.NO_WRAP))
                                .putString(PREF_IV, android.util.Base64.encodeToString(iv, android.util.Base64.NO_WRAP))
                                .apply()
                            
                            onResult(true, null)
                        } catch (e: Exception) {
                            onResult(false, e)
                        }
                    }

                    override fun onAuthenticationFailed() {
                        onResult(false, Exception("Authentication failed"))
                    }
                })

            biometricPrompt.authenticate(promptInfo, cryptoObject)

        } catch (e: Exception) {
            Log.e(TAG, "savePinWithBiometrics error", e)
            onResult(false, e)
        }
    }

    fun retrievePinWithBiometrics(activity: FragmentActivity, onResult: (CharArray?, Exception?) -> Unit) {
        if (!hasSavedPin()) {
            onResult(null, Exception("No saved PIN"))
            return
        }

        try {
            val key = ks.getKey(KEY_ALIAS, null) as? SecretKey ?: throw Exception("Key not found")
            val encryptedBase64 = prefs.getString(PREF_ENCRYPTED_PIN, null) ?: throw Exception("Missing encrypted PIN")
            val ivBase64 = prefs.getString(PREF_IV, null) ?: throw Exception("Missing IV")

            val encrypted = android.util.Base64.decode(encryptedBase64, android.util.Base64.NO_WRAP)
            val iv = android.util.Base64.decode(ivBase64, android.util.Base64.NO_WRAP)

            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, iv))

            val promptInfo = BiometricPrompt.PromptInfo.Builder()
                .setTitle("Unlock PIN")
                .setSubtitle("Authenticate to retrieve your secure PIN")
                .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG or BiometricManager.Authenticators.DEVICE_CREDENTIAL)
                .build()

            val cryptoObject = BiometricPrompt.CryptoObject(cipher)

            val biometricPrompt = BiometricPrompt(activity, ContextCompat.getMainExecutor(activity),
                object : BiometricPrompt.AuthenticationCallback() {
                    override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                        onResult(null, Exception("Auth error: $errString"))
                    }

                    override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                        try {
                            val authCipher = result.cryptoObject?.cipher ?: throw Exception("Cipher is null")
                            val decrypted = authCipher.doFinal(encrypted)
                            val pinChars = String(decrypted, StandardCharsets.UTF_8).toCharArray()
                            decrypted.fill(0) // Wipe byte array
                            onResult(pinChars, null)
                        } catch (e: Exception) {
                            // Key might have been invalidated due to new biometric enrollment
                            prefs.edit().clear().apply() 
                            onResult(null, e)
                        }
                    }

                    override fun onAuthenticationFailed() {
                        onResult(null, Exception("Authentication failed"))
                    }
                })

            biometricPrompt.authenticate(promptInfo, cryptoObject)

        } catch (e: Exception) {
            Log.e(TAG, "retrievePinWithBiometrics error", e)
            // Invalid key / User not authenticated
            onResult(null, e)
        }
    }
}
