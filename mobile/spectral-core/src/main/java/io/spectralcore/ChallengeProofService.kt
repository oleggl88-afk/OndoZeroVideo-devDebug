package io.spectralcore

import android.content.Context
import android.util.Log
import io.spectralcore.solana.*
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest
import kotlin.system.measureNanoTime

/**
 * Challenge-Response ZKP over Solana.
 *
 * Scheme:
 *   requestChallenge → on-chain ChallengeAccount PDA = ["challenge", gsh_seed]
 *   submitProof      → Ed25519 pre-ix + submit_proof ix
 *
 * Ed25519 msg for submitProof = SHA256("oz_spectral_proof_v1" || gsh || challenge_R || proof_P)
 *
 * @param identityService  App-specific DeviceIdentityService instance (holds DeviceTeeKey).
 */
class ChallengeProofService(
    private val identityService: DeviceIdentityService,
    private val spectralIdStore: SpectralIdStore,
    private val spectralEngine: SpectralEngine,
) {

    companion object {
        private const val TAG = "ChallengeProofService"
    }

    private val DISC_REQUEST_CHALLENGE = disc("global:request_challenge")
    private val DISC_SUBMIT_PROOF      = disc("global:submit_proof")

    // ── request_challenge ─────────────────────────────────────────────────────
    // Sends tx, waits for signature confirmation, then polls ChallengeAccount → returns R (32 bytes).

    fun requestChallenge(
        rpcUrl: String,
        programIdB58: String,
        wallet: SolanaWallet.Keypair,
        gshBytes: ByteArray
    ): ByteArray {
        require(gshBytes.size == 32)
        val programId    = Base58.decode(programIdB58)
        val devicePda    = SolanaTx.findPda(identityService.pdaDevice(gshBytes), programId)
        val challengePda = SolanaTx.findPda(pdaChallenge(gshBytes), programId)

        val instrData = ByteBuffer.allocate(8).put(DISC_REQUEST_CHALLENGE).array()
        val accounts = listOf(
            AccountMeta(challengePda,    writable = true,  signer = false),
            AccountMeta(devicePda,       writable = false, signer = false),
            AccountMeta(wallet.publicKey, writable = true, signer = true),
            AccountMeta(SYSTEM_PROGRAM,  writable = false, signer = false),
        )
        val blockhash = SolanaRpc.getLatestBlockhash(rpcUrl)
        val message   = SolanaTx.buildMessage(wallet.publicKey,
            listOf(Instruction(programId, accounts, instrData)), blockhash)
        val tx = SolanaTx.buildTransaction(listOf(SolanaWallet.sign(wallet.privateKey, message)), message)
        val txSig = SolanaRpc.sendTransaction(rpcUrl,
            android.util.Base64.encodeToString(tx, android.util.Base64.NO_WRAP))
        SolanaRpc.confirmSignature(rpcUrl, txSig)

        // ChallengeAccount: disc(8)+owner(32)+challenge(32)+expires_at(8)+bump(1)
        val data = awaitChallengeAccountData(rpcUrl, Base58.encode(challengePda))
        require(data.size >= 72) { "ChallengeAccount too small: ${data.size}" }
        return data.copyOfRange(40, 72)   // challenge R field
    }

    // ── submit_proof ──────────────────────────────────────────────────────────
    // Ed25519 msg = SHA256("oz_spectral_proof_v1" || gsh || challenge_R || proof_P)

    fun submitProof(
        rpcUrl: String,
        programIdB58: String,
        wallet: SolanaWallet.Keypair,
        context: Context,
        gshBytes: ByteArray,
        challengeR: ByteArray
    ): TxResult = runCatching {
        require(gshBytes.size == 32 && challengeR.size == 32)
        val programId = Base58.decode(programIdB58)
        val totalStartedAt = System.nanoTime()

        lateinit var proofP: ByteArray
        val computeProofNs = measureNanoTime {
            val thetaSeed = spectralIdStore.getTheta(context)
            proofP = spectralEngine.GSH_R_P_computeSpectralProofP(thetaSeed, challengeR)
        }

        lateinit var teePubkey: ByteArray
        lateinit var msg: ByteArray
        lateinit var ed25519Ix: ByteArray
        val teeSignNs = measureNanoTime {
            teePubkey = identityService.getAuthPublicKey(context, wallet.privateKey)
            msg = sha256("oz_spectral_proof_v1", gshBytes, challengeR, proofP)
            ed25519Ix = buildEd25519VerifyIxData(
                teePubkey,
                msg,
                identityService.signAuth(context, wallet.privateKey, msg)
            )
        }

        val devicePda    = SolanaTx.findPda(identityService.pdaDevice(gshBytes), programId)
        val challengePda = SolanaTx.findPda(pdaChallenge(gshBytes), programId)

        val submitData = ByteBuffer.allocate(8 + 32).order(ByteOrder.LITTLE_ENDIAN)
            .put(DISC_SUBMIT_PROOF)
            .put(proofP)
            .array()
        val accounts = listOf(
            AccountMeta(devicePda,        writable = true,  signer = false),
            AccountMeta(challengePda,     writable = true,  signer = false),
            AccountMeta(wallet.publicKey,  writable = true, signer = true),
            AccountMeta(SYSVAR_INSTRUCTIONS, writable = false, signer = false),
            AccountMeta(SYSTEM_PROGRAM,   writable = false, signer = false), // Bug #3 fix
        )
        lateinit var tx: ByteArray
        val buildTxNs = measureNanoTime {
            tx = buildSubmitProofTx(
                rpcUrl = rpcUrl,
                wallet = wallet,
                programId = programId,
                accounts = accounts,
                ed25519Ix = ed25519Ix,
                submitData = submitData,
            )
        }

        lateinit var sig: String
        val sendTxNs = measureNanoTime {
            sig = SolanaRpc.sendTransaction(rpcUrl,
                android.util.Base64.encodeToString(tx, android.util.Base64.NO_WRAP))
        }
        val confirmTxMs = SolanaRpc.confirmSignature(rpcUrl, sig)
        val totalMs = (System.nanoTime() - totalStartedAt) / 1_000_000.0
        Log.i(TAG, "submitProof confirmed: $sig")
        TxResult(
            ok = true,
            signature = sig,
            proofHex = toHex(proofP),
            challengeHex = toHex(challengeR),
            computeProofMs = computeProofNs / 1_000_000.0,
            teeSignMs = teeSignNs / 1_000_000.0,
            buildTxMs = buildTxNs / 1_000_000.0,
            sendTxMs = sendTxNs / 1_000_000.0,
            confirmTxMs = confirmTxMs,
            totalMs = totalMs,
        )
    }.getOrElse { e ->
        Log.e(TAG, "submitProof failed", e)
        TxResult(ok = false, errorDetail = "${e.javaClass.simpleName}: ${e.message}\n\nRPC: $rpcUrl")
    }

    fun refreshDeviceAuthorization(
        rpcUrl: String,
        programIdB58: String,
        wallet: SolanaWallet.Keypair,
        context: Context,
        gshBytes: ByteArray,
    ): TxResult = runCatching {
        val challengeR = requestChallenge(rpcUrl, programIdB58, wallet, gshBytes)
        submitProof(rpcUrl, programIdB58, wallet, context, gshBytes, challengeR)
    }.getOrElse { e ->
        Log.e(TAG, "refreshDeviceAuthorization failed", e)
        TxResult(ok = false, errorDetail = "${e.javaClass.simpleName}: ${e.message}\n\nRPC: $rpcUrl")
    }

    // ── Helpers ────────────────────────────────────────────────────────────────

    internal fun pdaChallenge(gshBytes: ByteArray) =
        listOf("challenge".toByteArray(Charsets.UTF_8), gshBytes)

    internal fun sha256(prefix: String, vararg parts: ByteArray): ByteArray {
        val md = MessageDigest.getInstance("SHA-256")
        md.update(prefix.toByteArray(Charsets.UTF_8))
        for (p in parts) md.update(p)
        return md.digest()
    }

    private fun buildSubmitProofTx(
        rpcUrl: String,
        wallet: SolanaWallet.Keypair,
        programId: ByteArray,
        accounts: List<AccountMeta>,
        ed25519Ix: ByteArray,
        submitData: ByteArray,
    ): ByteArray {
        val blockhash = SolanaRpc.getLatestBlockhash(rpcUrl)
        val message = SolanaTx.buildMessage(wallet.publicKey,
            listOf(
                Instruction(ED25519_PROGRAM, emptyList(), ed25519Ix),
                Instruction(programId, accounts, submitData)
            ), blockhash)
        return SolanaTx.buildTransaction(listOf(SolanaWallet.sign(wallet.privateKey, message)), message)
    }

    private fun awaitChallengeAccountData(rpcUrl: String, addressB58: String, timeoutMs: Long = 5_000L, pollIntervalMs: Long = 100L): ByteArray {
        val deadline = System.currentTimeMillis() + timeoutMs
        var lastError: Exception? = null
        while (System.currentTimeMillis() <= deadline) {
            try {
                return SolanaRpc.getAccountData(rpcUrl, addressB58)
            } catch (e: Exception) {
                lastError = e
                Thread.sleep(pollIntervalMs)
            }
        }
        throw RuntimeException("Challenge account $addressB58 was not readable within ${timeoutMs}ms", lastError)
    }
}
