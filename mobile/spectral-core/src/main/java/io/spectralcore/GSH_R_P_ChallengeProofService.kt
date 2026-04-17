package io.spectralcore

import android.content.Context
import android.util.Log
import io.spectralcore.solana.fromHex
import kotlin.system.measureNanoTime

/**
 * Manual/diagnostic helper around the production GSH + R + P flow.
 *
 * This class is kept for benchmark tooling and artifact inspection, while the
 * canonical production path remains ChallengeProofService.
 */
data class GSH_R_P_ProofArtifacts(
    val gshBytes: ByteArray,
    val challengeR: ByteArray,
    val proofP: ByteArray,
    val teePubkey: ByteArray,
    val messageToSign: ByteArray,
    val teeSignature: ByteArray,
    val requestChallengeMs: Double,
    val computeProofMs: Double,
    val teeSignMs: Double,
)

class GSH_R_P_ChallengeProofService(
    private val spectralIdStore: SpectralIdStore,
    private val spectralEngine: SpectralEngine,
    private val identityService: DeviceIdentityService,
) {
    companion object {
        private const val TAG = "GSH_R_P_ChallengeProofService"
        private const val DOMAIN = "oz_spectral_proof_v1"
    }

    private val baseChallengeProofService = ChallengeProofService(identityService, spectralIdStore, spectralEngine)

    fun GSH_R_P_requestChallenge(
        rpcUrl: String,
        programIdB58: String,
        wallet: SolanaWallet.Keypair,
        gshBytes: ByteArray,
    ): Pair<ByteArray, Double> {
        lateinit var challengeR: ByteArray
        val elapsedNs = measureNanoTime {
            challengeR = baseChallengeProofService.requestChallenge(rpcUrl, programIdB58, wallet, gshBytes)
        }
        val elapsedMs = elapsedNs / 1_000_000.0
        Log.d(TAG, "GSH_R_P_requestChallenge: ${challengeR.toHex().take(16)}… in ${"%.3f".format(elapsedMs)} ms")
        return challengeR to elapsedMs
    }

    fun GSH_R_P_computeSpectralProofP(
        context: Context,
        challengeR: ByteArray,
    ): Pair<ByteArray, Double> {
        require(challengeR.size == 32) { "challengeR must be 32 bytes" }

        val thetaSeed = spectralIdStore.getTheta(context)
        lateinit var proofP: ByteArray
        val elapsedNs = measureNanoTime {
            proofP = spectralEngine.GSH_R_P_computeSpectralProofP(thetaSeed, challengeR)
        }
        val elapsedMs = elapsedNs / 1_000_000.0
        Log.d(TAG, "GSH_R_P_computeSpectralProofP: ${proofP.toHex().take(16)}… in ${"%.3f".format(elapsedMs)} ms")
        return proofP to elapsedMs
    }

    fun GSH_R_P_buildProofMessage(
        gshBytes: ByteArray,
        challengeR: ByteArray,
        proofP: ByteArray,
    ): ByteArray {
        require(gshBytes.size == 32) { "gshBytes must be 32 bytes" }
        require(challengeR.size == 32) { "challengeR must be 32 bytes" }
        require(proofP.size == 32) { "proofP must be 32 bytes" }
        return sha256(DOMAIN.toByteArray(Charsets.UTF_8), gshBytes, challengeR, proofP)
    }

    fun GSH_R_P_signProofMessage(
        context: Context,
        wallet: SolanaWallet.Keypair,
        messageToSign: ByteArray,
    ): Triple<ByteArray, ByteArray, Double> {
        require(messageToSign.size == 32) { "messageToSign must be 32 bytes" }

        lateinit var teePubkey: ByteArray
        lateinit var teeSignature: ByteArray
        val elapsedNs = measureNanoTime {
            teePubkey = identityService.getAuthPublicKey(context, wallet.privateKey)
            teeSignature = identityService.signAuth(context, wallet.privateKey, messageToSign)
        }
        val elapsedMs = elapsedNs / 1_000_000.0
        Log.d(TAG, "GSH_R_P_signProofMessage: teePubkey=${teePubkey.toHex().take(16)}… in ${"%.3f".format(elapsedMs)} ms")
        return Triple(teePubkey, teeSignature, elapsedMs)
    }

    fun GSH_R_P_prepareProofArtifacts(
        rpcUrl: String,
        programIdB58: String,
        wallet: SolanaWallet.Keypair,
        context: Context,
    ): GSH_R_P_ProofArtifacts {
        val gshHex = spectralIdStore.getOrCreate(context)
        val gshBytes = fromHex(gshHex)
        val (challengeR, requestChallengeMs) = GSH_R_P_requestChallenge(rpcUrl, programIdB58, wallet, gshBytes)
        val (proofP, computeProofMs) = GSH_R_P_computeSpectralProofP(context, challengeR)
        val messageToSign = GSH_R_P_buildProofMessage(gshBytes, challengeR, proofP)
        val (teePubkey, teeSignature, teeSignMs) = GSH_R_P_signProofMessage(context, wallet, messageToSign)

        return GSH_R_P_ProofArtifacts(
            gshBytes = gshBytes,
            challengeR = challengeR,
            proofP = proofP,
            teePubkey = teePubkey,
            messageToSign = messageToSign,
            teeSignature = teeSignature,
            requestChallengeMs = requestChallengeMs,
            computeProofMs = computeProofMs,
            teeSignMs = teeSignMs,
        )
    }

    private fun sha256(vararg parts: ByteArray): ByteArray {
        val md = java.security.MessageDigest.getInstance("SHA-256")
        for (part in parts) {
            md.update(part)
        }
        return md.digest()
    }

    private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }
}
