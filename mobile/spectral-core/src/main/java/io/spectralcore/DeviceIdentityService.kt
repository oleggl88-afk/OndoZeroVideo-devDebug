package io.spectralcore

import android.content.Context
import android.util.Log
import io.spectralcore.solana.*
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest

/**
 * Manages device account lifecycle on Solana.
 *
 * DeviceAccount PDA = ["device", gsh_seed]
 * tee_pubkey        = Ed25519 public key from DeviceTeeKey (hardware-backed).
 *
 * Each method with Ed25519 builds two instructions in one transaction:
 *   1. Ed25519SigVerify  ← proof of TEE key ownership
 *   2. Anchor instruction ← the actual on-chain operation
 *
 * @param teeKey  App-specific DeviceTeeKey instance.
 * @param guardianPubkeyBase58 Network-selected guardian pubkey used during registration.
 */
class DeviceIdentityService(
    private val teeKey: DeviceTeeKey,
    private val guardianPubkeyBase58: String,
) {

    companion object {
        private const val TAG = "DeviceIdentityService"
    }

    private val guardianPubkey: ByteArray by lazy(LazyThreadSafetyMode.NONE) {
        val normalized = guardianPubkeyBase58.trim()
        require(normalized.isNotEmpty()) { "Guardian pubkey is not configured for this build" }
        Base58.decode(normalized)
    }

    private val DISC_REGISTER_DEVICE    = disc("global:register_device")
    private val DISC_MIGRATE_OWNER      = disc("global:migrate_owner")
    private val DISC_START_HANDOVER     = disc("global:start_handover")
    private val DISC_COMPLETE_HANDOVER  = disc("global:complete_handover")

    // ── TEE key helpers ────────────────────────────────────────────────────────

    fun getAuthPublicKey(context: Context, walletSeed: ByteArray): ByteArray = teeKey.publicKeyBytes(context, walletSeed)

    internal fun signAuth(context: Context, walletSeed: ByteArray, message: ByteArray): ByteArray =
        teeKey.sign(context, walletSeed, message)

    // ── register_device ───────────────────────────────────────────────────────
    // Ed25519 msg = SHA256("oz_register_v1" || gsh_seed || tee_pubkey)

    fun registerDevice(
        rpcUrl: String,
        programIdB58: String,
        wallet: SolanaWallet.Keypair,
        gshBytes: ByteArray,
        context: Context
    ): TxResult = runCatching {
        require(gshBytes.size == 32)
        val programId = Base58.decode(programIdB58)
        val teePubkey = getAuthPublicKey(context, wallet.privateKey)

        val msg       = sha256("oz_register_v1", gshBytes, teePubkey)
        val ed25519Ix = buildEd25519VerifyIxData(teePubkey, msg, signAuth(context, wallet.privateKey, msg))

        val devicePda      = SolanaTx.findPda(pdaDevice(gshBytes), programId)
        val walletRegPda   = SolanaTx.findPda(pdaWalletRegistry(wallet.publicKey), programId)
        Log.d(TAG, "registerDevice PDA=${Base58.encode(devicePda)} walletReg=${Base58.encode(walletRegPda)}")

        // Derive hardware attestation fingerprint.  On certified devices this is
        // SHA-256(cert[1].encoded) — unique to the physical TEE, same across all Android
        // user profiles (main / Second Space).  Falls back to SHA-256(gsh) on emulators.
        val attestationData = teeKey.getAttestationFingerprint(context, gshBytes)
        val attestBinderPda = SolanaTx.findPda(pdaAttestBinder(attestationData), programId)
        Log.d(TAG, "registerDevice attestBinder=${Base58.encode(attestBinderPda)}")

        val instrData = ByteBuffer.allocate(8 + 32 + 32 + 32).order(ByteOrder.LITTLE_ENDIAN)
            .put(DISC_REGISTER_DEVICE).put(gshBytes).put(teePubkey).put(attestationData).array()

        val accounts = listOf(
            AccountMeta(devicePda,        writable = true,  signer = false),
            AccountMeta(walletRegPda,     writable = true,  signer = false), // wallet_registry (init, prevents double-register)
            AccountMeta(attestBinderPda,  writable = true,  signer = false), // attest_binder (init, blocks Second Space re-registration)
            AccountMeta(wallet.publicKey, writable = true,  signer = true),
            AccountMeta(guardianPubkey,   writable = false, signer = false),
            AccountMeta(SYSVAR_INSTRUCTIONS, writable = false, signer = false),
            AccountMeta(SYSTEM_PROGRAM,   writable = false, signer = false),
        )
        val tx = buildAndSignTx(rpcUrl, wallet.publicKey,
            listOf(
                Instruction(ED25519_PROGRAM, emptyList(), ed25519Ix),
                Instruction(programId, accounts, instrData)
            ),
            listOf(wallet.privateKey)
        )
        val sig = SolanaRpc.sendTransaction(rpcUrl, tx)
        Log.i(TAG, "registerDevice confirmed: $sig")
        TxResult(ok = true, signature = sig)
    }.getOrElse { e ->
        Log.e(TAG, "registerDevice failed", e)
        TxResult(ok = false, errorDetail = "${e.javaClass.simpleName}: ${e.message}\n\nRPC: $rpcUrl")
    }

    // ── update_tee_pubkey ─────────────────────────────────────────────────────
    // Ed25519 msg = SHA256("oz_update_tee_v2" || device_pda || new_tee_pubkey)
    // Signed by the CURRENT tee_pubkey after a fresh challenge/proof.
    // This is no longer a reinstall recovery path or wallet migration shortcut.

    fun updateTeePubkey(
        rpcUrl: String,
        programIdB58: String,
        wallet: SolanaWallet.Keypair,
        gshBytes: ByteArray,
        context: Context
    ): TxResult = runCatching {
        require(gshBytes.size == 32)
        val programId = Base58.decode(programIdB58)
        val teePubkey = getAuthPublicKey(context, wallet.privateKey)
        val devicePda = SolanaTx.findPda(pdaDevice(gshBytes), programId)

        val onChainInfo = fetchDeviceAccount(rpcUrl, programIdB58, gshBytes)
            ?: error("DeviceAccount not found on-chain. This GSH is not registered.")
        val onChainOwner    = Base58.decode(onChainInfo.ownerBase58)

        val msg       = sha256("oz_update_tee_v2", devicePda, teePubkey)
        val ed25519Ix = buildEd25519VerifyIxData(teePubkey, msg, signAuth(context, wallet.privateKey, msg))

        val walletRegPda = SolanaTx.findPda(pdaWalletRegistry(onChainOwner), programId)
        Log.d(TAG, "updateTeePubkey PDA=${Base58.encode(devicePda)} walletReg=${Base58.encode(walletRegPda)} onChain=${onChainInfo.ownerBase58} current=${Base58.encode(wallet.publicKey)}")

        val instrData = ByteBuffer.allocate(8 + 32 + 32).order(ByteOrder.LITTLE_ENDIAN)
            .put(disc("global:update_tee_pubkey")).put(gshBytes).put(teePubkey).array()

        val accounts = listOf(
            AccountMeta(devicePda,           writable = true,  signer = false),
            AccountMeta(walletRegPda,        writable = true,  signer = false),
            AccountMeta(wallet.publicKey,    writable = true,  signer = true),
            AccountMeta(SYSVAR_INSTRUCTIONS, writable = false, signer = false),
            AccountMeta(SYSTEM_PROGRAM,      writable = false, signer = false),
        )
        val tx = buildAndSignTx(rpcUrl, wallet.publicKey,
            listOf(
                Instruction(ED25519_PROGRAM, emptyList(), ed25519Ix),
                Instruction(programId, accounts, instrData)
            ),
            listOf(wallet.privateKey)
        )
        val sig = SolanaRpc.sendTransaction(rpcUrl, tx)
        Log.i(TAG, "updateTeePubkey confirmed: $sig")

        TxResult(ok = true, signature = sig)
    }.getOrElse { e ->
        Log.e(TAG, "updateTeePubkey failed", e)
        TxResult(ok = false, errorDetail = "${e.javaClass.simpleName}: ${e.message}\n\nRPC: $rpcUrl")
    }

    // ── migrate_owner ─────────────────────────────────────────────────────────
    // Ed25519 msg = SHA256("oz_migrate_v1" || device_pda || new_owner || nonce_LE8)

    fun migrateOwner(
        rpcUrl: String,
        programIdB58: String,
        newOwnerWallet: SolanaWallet.Keypair,
        context: Context,
        gshBytes: ByteArray,
        currentNonce: Long
    ): TxResult = runCatching {
        require(gshBytes.size == 32)
        val programId = Base58.decode(programIdB58)
        val teePubkey = getAuthPublicKey(context, newOwnerWallet.privateKey)
        val devicePda       = SolanaTx.findPda(pdaDevice(gshBytes), programId)

        // Fetch current owner from on-chain account to compute old_wallet_registry PDA.
        // The contract also verifies seeds=[b"wallet_reg", device_account.owner] so this
        // must match exactly.
        val currentOwnerBase58 = fetchDeviceAccount(rpcUrl, programIdB58, gshBytes)?.ownerBase58
            ?: error("DeviceAccount not found — cannot migrate unregistered device")
        val currentOwner     = Base58.decode(currentOwnerBase58)
        val oldWalletRegPda = SolanaTx.findPda(pdaWalletRegistry(currentOwner), programId)
        val newWalletRegPda = SolanaTx.findPda(pdaWalletRegistry(newOwnerWallet.publicKey), programId)

        val nonceLE   = ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN).putLong(currentNonce).array()
        val msg       = sha256("oz_migrate_v1", devicePda, newOwnerWallet.publicKey, nonceLE)
        val ed25519Ix = buildEd25519VerifyIxData(teePubkey, msg, signAuth(context, newOwnerWallet.privateKey, msg))

        val instrData = ByteBuffer.allocate(8 + 32).order(ByteOrder.LITTLE_ENDIAN)
            .put(DISC_MIGRATE_OWNER).put(gshBytes).array()
        val accounts = listOf(
            AccountMeta(devicePda,         writable = true,  signer = false),
            AccountMeta(oldWalletRegPda,   writable = true,  signer = false), // closed → refunded to newOwner
            AccountMeta(newWalletRegPda,   writable = true,  signer = false), // init, blocks if newOwner already registered
            AccountMeta(newOwnerWallet.publicKey, writable = true, signer = true),
            AccountMeta(SYSVAR_INSTRUCTIONS, writable = false, signer = false),
            AccountMeta(SYSTEM_PROGRAM,    writable = false, signer = false),
        )
        val tx = buildAndSignTx(rpcUrl, newOwnerWallet.publicKey,
            listOf(
                Instruction(ED25519_PROGRAM, emptyList(), ed25519Ix),
                Instruction(programId, accounts, instrData)
            ),
            listOf(newOwnerWallet.privateKey)
        )
        val sig = SolanaRpc.sendTransaction(rpcUrl, tx)
        Log.i(TAG, "migrateOwner confirmed: $sig")
        TxResult(ok = true, signature = sig)
    }.getOrElse { e ->
        Log.e(TAG, "migrateOwner failed", e)
        TxResult(ok = false, errorDetail = "${e.javaClass.simpleName}: ${e.message}")
    }

    // ── start_handover ────────────────────────────────────────────────────────
    // Initiates device-to-device identity transfer.
    // Old device TEE signs: SHA256("oz_handover_v1" || gsh_old || gsh_new || new_device_pda)
    // Sets old DeviceAccount status = 2 (GracePeriod), records target GSH and deadline.
    // New device must already be registered on-chain independently.

    fun startHandover(
        rpcUrl: String,
        programIdB58: String,
        wallet: SolanaWallet.Keypair,
        oldGshBytes: ByteArray,
        newGshBytes: ByteArray,
        context: Context,
        graceSeconds: Long = 14L * 24 * 60 * 60
    ): TxResult = runCatching {
        require(oldGshBytes.size == 32) { "oldGshBytes must be 32 bytes" }
        require(newGshBytes.size == 32) { "newGshBytes must be 32 bytes" }
        val programId = Base58.decode(programIdB58)
        val teePubkey = getAuthPublicKey(context, wallet.privateKey)

        val oldDevicePda = SolanaTx.findPda(pdaDevice(oldGshBytes), programId)
        val newDevicePda = SolanaTx.findPda(pdaDevice(newGshBytes), programId)

        val msg = sha256("oz_handover_v1", oldGshBytes, newGshBytes, newDevicePda)
        val ed25519Ix = buildEd25519VerifyIxData(teePubkey, msg, signAuth(context, wallet.privateKey, msg))

        // Instruction data: disc(8) + gsh_seed(32) + target_gsh(32) + grace_seconds(8 LE)
        val instrData = ByteBuffer.allocate(8 + 32 + 32 + 8).order(ByteOrder.LITTLE_ENDIAN)
            .put(DISC_START_HANDOVER)
            .put(oldGshBytes)
            .put(newGshBytes)
            .putLong(graceSeconds)
            .array()

        val accounts = listOf(
            AccountMeta(oldDevicePda,        writable = true,  signer = false),
            AccountMeta(newDevicePda,        writable = false, signer = false),
            AccountMeta(wallet.publicKey,    writable = true,  signer = true),
            AccountMeta(SYSVAR_INSTRUCTIONS, writable = false, signer = false),
            AccountMeta(SYSTEM_PROGRAM,      writable = false, signer = false),
        )
        val tx = buildAndSignTx(rpcUrl, wallet.publicKey,
            listOf(
                Instruction(ED25519_PROGRAM, emptyList(), ed25519Ix),
                Instruction(programId, accounts, instrData)
            ),
            listOf(wallet.privateKey)
        )
        val sig = SolanaRpc.sendTransaction(rpcUrl, tx)
        Log.i(TAG, "startHandover confirmed: $sig  old=${oldGshBytes.joinToString("") { "%02x".format(it) }.take(8)}… → new=${newGshBytes.joinToString("") { "%02x".format(it) }.take(8)}…")
        TxResult(ok = true, signature = sig)
    }.getOrElse { e ->
        Log.e(TAG, "startHandover failed", e)
        TxResult(ok = false, errorDetail = "${e.javaClass.simpleName}: ${e.message}")
    }

    fun completeHandover(
        rpcUrl: String,
        programIdB58: String,
        wallet: SolanaWallet.Keypair,
        oldGshBytes: ByteArray,
        newGshBytes: ByteArray,
        context: Context,
    ): TxResult = runCatching {
        require(oldGshBytes.size == 32) { "oldGshBytes must be 32 bytes" }
        require(newGshBytes.size == 32) { "newGshBytes must be 32 bytes" }

        val programId = Base58.decode(programIdB58)
        val teePubkey = getAuthPublicKey(context, wallet.privateKey)
        val attestationData = teeKey.getAttestationFingerprint(context, newGshBytes)

        val oldDevicePda = SolanaTx.findPda(pdaDevice(oldGshBytes), programId)
        val newDevicePda = SolanaTx.findPda(pdaDevice(newGshBytes), programId)
        val walletRegPda = SolanaTx.findPda(pdaWalletRegistry(wallet.publicKey), programId)
        val attestBinderPda = SolanaTx.findPda(pdaAttestBinder(attestationData), programId)

        val msg = sha256(
            "oz_complete_handover_v1",
            oldGshBytes,
            newGshBytes,
            wallet.publicKey,
            newDevicePda,
            teePubkey,
        )
        val ed25519Ix = buildEd25519VerifyIxData(teePubkey, msg, signAuth(context, wallet.privateKey, msg))

        val instrData = ByteBuffer.allocate(8 + 32 + 32 + 32 + 32).order(ByteOrder.LITTLE_ENDIAN)
            .put(DISC_COMPLETE_HANDOVER)
            .put(oldGshBytes)
            .put(newGshBytes)
            .put(teePubkey)
            .put(attestationData)
            .array()

        val accounts = listOf(
            AccountMeta(oldDevicePda,        writable = true,  signer = false),
            AccountMeta(newDevicePda,        writable = true,  signer = false),
            AccountMeta(walletRegPda,        writable = true,  signer = false),
            AccountMeta(attestBinderPda,     writable = true,  signer = false),
            AccountMeta(wallet.publicKey,    writable = true,  signer = true),
            AccountMeta(SYSVAR_INSTRUCTIONS, writable = false, signer = false),
            AccountMeta(SYSTEM_PROGRAM,      writable = false, signer = false),
        )
        val tx = buildAndSignTx(
            rpcUrl,
            wallet.publicKey,
            listOf(
                Instruction(ED25519_PROGRAM, emptyList(), ed25519Ix),
                Instruction(programId, accounts, instrData),
            ),
            listOf(wallet.privateKey)
        )
        val sig = SolanaRpc.sendTransaction(rpcUrl, tx)
        Log.i(
            TAG,
            "completeHandover confirmed: $sig old=${oldGshBytes.joinToString("") { "%02x".format(it) }.take(8)}… new=${newGshBytes.joinToString("") { "%02x".format(it) }.take(8)}…"
        )
        TxResult(ok = true, signature = sig)
    }.getOrElse { e ->
        Log.e(TAG, "completeHandover failed", e)
        TxResult(ok = false, errorDetail = "${e.javaClass.simpleName}: ${e.message}")
    }

    // ── DeviceAccountInfo ──────────────────────────────────────────────────────

    data class DeviceAccountInfo(
        val ownerBase58: String,
        val isActive: Boolean,
        val rootCount: Long,
        val teePubkey: ByteArray? = null,
        val status: Int = 0,
        val handoverTargetGsh: ByteArray? = null,
        val handoverGraceUntilEpochSeconds: Long? = null,
        val proofFreshUntilEpochSeconds: Long? = null,
    )

    /**
     * Returns parsed DeviceAccount if it exists on-chain, or null if not found.
     * Supports both the base layout and the extended handover-aware layout.
     */
    fun fetchDeviceAccount(
        rpcUrl: String,
        programIdB58: String,
        gshBytes: ByteArray
    ): DeviceAccountInfo? = runCatching {
        require(gshBytes.size == 32)
        val programId = Base58.decode(programIdB58)
        val devicePda = SolanaTx.findPda(pdaDevice(gshBytes), programId)
        val pdaB58    = Base58.encode(devicePda)
        Log.d(TAG, "fetchDeviceAccount PDA=$pdaB58")
        val data      = SolanaRpc.getAccountData(rpcUrl, pdaB58)
        require(data.size >= 121) { "DeviceAccount too small: ${data.size}" }
        val teePubkey = data.copyOfRange(40, 72)
        val owner     = Base58.encode(data.copyOfRange(72, 104))
        val isActive  = data[112] != 0.toByte()
        val rootCount = ByteBuffer.wrap(data.copyOfRange(113, 121)).order(ByteOrder.LITTLE_ENDIAN).long
        val status    = if (data.size >= 122) data[121].toInt() and 0xff else 0
        val handoverTargetGsh = if (data.size >= 226) data.copyOfRange(194, 226) else null
        val handoverGraceUntilEpochSeconds = if (data.size >= 234) {
            ByteBuffer.wrap(data.copyOfRange(226, 234)).order(ByteOrder.LITTLE_ENDIAN).long
        } else {
            null
        }
        val proofFreshUntilEpochSeconds = if (data.size >= 242) {
            ByteBuffer.wrap(data.copyOfRange(234, 242)).order(ByteOrder.LITTLE_ENDIAN).long
        } else {
            null
        }
        Log.i(TAG, "fetchDeviceAccount: owner=$owner active=$isActive roots=$rootCount")
        DeviceAccountInfo(
            ownerBase58 = owner,
            isActive = isActive,
            rootCount = rootCount,
            teePubkey = teePubkey,
            status = status,
            handoverTargetGsh = handoverTargetGsh,
            handoverGraceUntilEpochSeconds = handoverGraceUntilEpochSeconds,
            proofFreshUntilEpochSeconds = proofFreshUntilEpochSeconds,
        )
    }.getOrElse { e ->
        Log.d(TAG, "fetchDeviceAccount: not found or error — ${e.message}")
        null
    }

    /**
     * Returns true if the given wallet pubkey is already bound to a device via WalletRegistry PDA.
     * Returns false if the account does not exist (wallet is free to register or import).
     * Never throws — returns false on any RPC / parsing error.
     */
    fun fetchWalletRegistry(
        rpcUrl: String,
        programIdB58: String,
        walletPubkey: ByteArray
    ): Boolean = runCatching {
        require(walletPubkey.size == 32)
        val programId = Base58.decode(programIdB58)
        val regPda    = SolanaTx.findPda(pdaWalletRegistry(walletPubkey), programId)
        val pdaB58    = Base58.encode(regPda)
        Log.d(TAG, "fetchWalletRegistry PDA=$pdaB58")
        val data = SolanaRpc.getAccountData(rpcUrl, pdaB58)
        // WalletRegistry layout: discriminator(8) + gsh(32) + tee_pubkey(32) = 72 bytes
        data.size >= 72
    }.getOrElse { e ->
        Log.d(TAG, "fetchWalletRegistry: not found or error — ${e.message}")
        false
    }

    /**
     * Returns the 32-byte GSH bound to [walletPubkey] in WalletRegistry,
     * or null if the wallet is not registered (account absent or any error).
     * Layout: discriminator(8) + gsh(32) + tee_pubkey(32)
     */
    fun fetchWalletRegistryGsh(
        rpcUrl: String,
        programIdB58: String,
        walletPubkey: ByteArray
    ): ByteArray? = runCatching {
        require(walletPubkey.size == 32)
        val programId = Base58.decode(programIdB58)
        val regPda    = SolanaTx.findPda(pdaWalletRegistry(walletPubkey), programId)
        val pdaB58    = Base58.encode(regPda)
        Log.d(TAG, "fetchWalletRegistryGsh PDA=$pdaB58")
        val data = SolanaRpc.getAccountData(rpcUrl, pdaB58)
        // WalletRegistry layout: discriminator(8) + gsh(32) + tee_pubkey(32) = 72 bytes
        require(data.size >= 40) { "WalletRegistry account too small: ${data.size}" }
        data.copyOfRange(8, 40)  // GSH bytes
    }.getOrElse { e ->
        Log.d(TAG, "fetchWalletRegistryGsh: not found or error — ${e.message}")
        null
    }

    /**
     * Returns the 32-byte GSH claimed by the current physical-device attestation binder,
     * or null if no binder exists yet for this hardware fingerprint.
     * Layout: discriminator(8) + gsh(32)
     */
    fun fetchAttestationBinderGsh(
        rpcUrl: String,
        programIdB58: String,
        fingerprint: ByteArray,
    ): ByteArray? = runCatching {
        require(fingerprint.size == 32)
        val programId = Base58.decode(programIdB58)
        val binderPda = SolanaTx.findPda(pdaAttestBinder(fingerprint), programId)
        val pdaB58 = Base58.encode(binderPda)
        Log.d(TAG, "fetchAttestationBinderGsh PDA=$pdaB58")
        val data = SolanaRpc.getAccountData(rpcUrl, pdaB58)
        require(data.size >= 40) { "AttestationBinder account too small: ${data.size}" }
        data.copyOfRange(8, 40)
    }.getOrElse { e ->
        Log.d(TAG, "fetchAttestationBinderGsh: not found or error — ${e.message}")
        null
    }

    fun fetchDeviceNonce(rpcUrl: String, programIdB58: String, gshBytes: ByteArray): Long {
        val programId = Base58.decode(programIdB58)
        val devicePda = SolanaTx.findPda(pdaDevice(gshBytes), programId)
        val data      = SolanaRpc.getAccountData(rpcUrl, Base58.encode(devicePda))
        require(data.size >= 112) { "DeviceAccount too small: ${data.size}" }
        return ByteBuffer.wrap(data.copyOfRange(104, 112)).order(ByteOrder.LITTLE_ENDIAN).long
    }

    // ── Helpers ────────────────────────────────────────────────────────────────

    fun pdaDevice(gshBytes: ByteArray) =
        listOf("dev_v2".toByteArray(Charsets.UTF_8), gshBytes)

    /** Seeds: ["wallet_reg", owner_pubkey(32)] — one per Solana wallet. */
    fun pdaWalletRegistry(ownerPubkey: ByteArray) =
        listOf("wallet_reg".toByteArray(Charsets.UTF_8), ownerPubkey)

    /** Seeds: ["attest_v1", attestation_fingerprint(32)] — one per physical device hardware chain. */
    fun pdaAttestBinder(fingerprint: ByteArray) =
        listOf("attest_v1".toByteArray(Charsets.UTF_8), fingerprint)

    fun sha256(prefix: String, vararg parts: ByteArray): ByteArray {
        val md = MessageDigest.getInstance("SHA-256")
        md.update(prefix.toByteArray(Charsets.UTF_8))
        for (p in parts) md.update(p)
        return md.digest()
    }

    private fun buildAndSignTx(
        rpcUrl: String, feePayer: ByteArray,
        instructions: List<Instruction>, signerKeys: List<ByteArray>
    ): String {
        val blockhash  = SolanaRpc.getLatestBlockhash(rpcUrl)
        val message    = SolanaTx.buildMessage(feePayer, instructions, blockhash)
        val signatures = signerKeys.map { SolanaWallet.sign(it, message) }
        val tx         = SolanaTx.buildTransaction(signatures, message)
        return android.util.Base64.encodeToString(tx, android.util.Base64.NO_WRAP)
    }
}
