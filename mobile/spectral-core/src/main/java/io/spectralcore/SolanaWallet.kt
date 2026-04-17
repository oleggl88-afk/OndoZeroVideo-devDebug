package io.spectralcore

import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer

/**
 * Thin wallet signing shim for the TEE identity layer.
 * Pure signing only — does NOT store keys.
 * Key material is passed in from the caller (app's RN bridge or KeystoreWallet).
 */
object SolanaWallet {

    data class Keypair(val publicKey: ByteArray, val privateKey: ByteArray) {
        val publicKeyBase58: String get() = Base58.encode(publicKey)
    }

    fun sign(privateKeyBytes: ByteArray, message: ByteArray): ByteArray {
        val signer = Ed25519Signer()
        signer.init(true, Ed25519PrivateKeyParameters(privateKeyBytes))
        signer.update(message, 0, message.size)
        return signer.generateSignature()
    }

    /** Derives Keypair from a 32-byte Ed25519 seed (first 32 bytes of @solana/web3.js secretKey). */
    fun keypairFromSeed(seed: ByteArray): Keypair {
        require(seed.size == 32) { "Ed25519 seed must be exactly 32 bytes" }
        val priv = Ed25519PrivateKeyParameters(seed)
        val pub  = priv.generatePublicKey().encoded  // 32 bytes
        return Keypair(publicKey = pub, privateKey = seed)
    }
}
