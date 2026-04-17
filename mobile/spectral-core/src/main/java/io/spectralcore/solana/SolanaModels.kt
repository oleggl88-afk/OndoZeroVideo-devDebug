package io.spectralcore.solana

import io.spectralcore.Base58
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest

// ── Anchor discriminator ───────────────────────────────────────────────────────
fun disc(name: String): ByteArray =
    MessageDigest.getInstance("SHA-256")
        .digest(name.toByteArray(Charsets.UTF_8))
        .take(8).toByteArray()

// ── Well-known program addresses ──────────────────────────────────────────────
val SYSTEM_PROGRAM:       ByteArray = Base58.decode("11111111111111111111111111111111")
val ED25519_PROGRAM:      ByteArray = Base58.decode("Ed25519SigVerify111111111111111111111111111")
val MEMO_PROGRAM:         ByteArray = Base58.decode("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr")
val SYSVAR_INSTRUCTIONS:  ByteArray = Base58.decode("Sysvar1nstructions1111111111111111111111111")

// ── Transaction result ────────────────────────────────────────────────────────
data class TxResult(
    val ok: Boolean,
    val signature: String  = "",
    val segmentRecordAddress: String = "",
    val errorDetail: String = "",
    val proofHex: String = "",
    val challengeHex: String = "",
    val computeProofMs: Double = 0.0,
    val teeSignMs: Double = 0.0,
    val buildTxMs: Double = 0.0,
    val sendTxMs: Double = 0.0,
    val confirmTxMs: Double = 0.0,
    val totalMs: Double = 0.0,
)

// ── Transaction primitives ────────────────────────────────────────────────────
data class AccountMeta(val pubkey: ByteArray, val writable: Boolean, val signer: Boolean)
data class Instruction(val programId: ByteArray, val accounts: List<AccountMeta>, val data: ByteArray)
data class AddressSignatureInfo(val signature: String, val blockTime: Long?)
data class TransactionMemoInfo(val signature: String, val blockTime: Long?, val memo: String?)

// ── Ed25519SigVerify instruction data ─────────────────────────────────────────
// Layout: header(16) + sig(64) + pubkey(32) + msg(32) = 144 bytes
// [count=1][pad][sig_off=16][0xFFFF][pk_off=80][0xFFFF][msg_off=112][32][0xFFFF]
fun buildEd25519VerifyIxData(pubkey: ByteArray, message: ByteArray, signature: ByteArray): ByteArray {
    require(pubkey.size == 32 && message.size == 32 && signature.size == 64)
    val buf = ByteBuffer.allocate(144).order(ByteOrder.LITTLE_ENDIAN)
    buf.put(1.toByte())                        // count = 1
    buf.put(0.toByte())                        // padding
    buf.putShort(16)                           // sig offset
    buf.putShort(-1)                           // sig ix index = 0xFFFF (current)
    buf.putShort((16 + 64).toShort())          // pubkey offset = 80
    buf.putShort(-1)                           // pubkey ix index
    buf.putShort((16 + 64 + 32).toShort())     // msg offset = 112
    buf.putShort(32)                           // msg size
    buf.putShort(-1)                           // msg ix index
    buf.put(signature)
    buf.put(pubkey)
    buf.put(message)
    return buf.array()
}

// ── Hex helpers (package-internal) ───────────────────────────────────────────
fun fromHex(s: String): ByteArray =
    ByteArray(s.length / 2) { i -> s.substring(i * 2, i * 2 + 2).toInt(16).toByte() }

internal fun toHex(b: ByteArray) = b.joinToString("") { "%02x".format(it) }
