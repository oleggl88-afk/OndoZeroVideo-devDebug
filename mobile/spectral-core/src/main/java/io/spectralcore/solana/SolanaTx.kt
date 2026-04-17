package io.spectralcore.solana

import io.spectralcore.Base58
import java.security.MessageDigest

/**
 * Stateless Solana transaction builder + PDA derivation.
 * No network calls — pure byte manipulation.
 */
object SolanaTx {

    fun buildMessage(
        feePayer: ByteArray,
        instructions: List<Instruction>,
        blockhashB58: String
    ): ByteArray {
        data class AccInfo(val pubkey: ByteArray, var writable: Boolean, var signer: Boolean)
        val accMap = linkedMapOf<String, AccInfo>()
        fun add(pk: ByteArray, w: Boolean, s: Boolean) {
            val key = toHex(pk)
            val cur = accMap[key]
            if (cur == null) accMap[key] = AccInfo(pk, w, s)
            else { cur.writable = cur.writable || w; cur.signer = cur.signer || s }
        }
        add(feePayer, true, true)
        for (ix in instructions) {
            for (am in ix.accounts) add(am.pubkey, am.writable, am.signer)
            add(ix.programId, false, false)
        }
        val sorted = accMap.values.sortedWith(compareBy(
            { if (it.signer)   0 else 1 },
            { if (it.writable) 0 else 1 }
        ))
        val numReqSig     = sorted.count {  it.signer }.toByte()
        val numROSigned   = sorted.count {  it.signer && !it.writable }.toByte()
        val numROUnsigned = sorted.count { !it.signer && !it.writable }.toByte()
        fun idx(pk: ByteArray) = sorted.indexOfFirst { toHex(it.pubkey) == toHex(pk) }

        val buf = mutableListOf<Byte>()
        buf += numReqSig
        buf += numROSigned
        buf += numROUnsigned
        writeCompactU16(buf, sorted.size)
        for (acc in sorted) buf += acc.pubkey
        buf += Base58.decode(blockhashB58)
        writeCompactU16(buf, instructions.size)
        for (ix in instructions) {
            buf += idx(ix.programId).toByte()
            writeCompactU16(buf, ix.accounts.size)
            for (am in ix.accounts) buf += idx(am.pubkey).toByte()
            writeCompactU16(buf, ix.data.size)
            buf += ix.data
        }
        return buf.toByteArray()
    }

    fun buildTransaction(signatures: List<ByteArray>, message: ByteArray): ByteArray {
        val buf = mutableListOf<Byte>()
        writeCompactU16(buf, signatures.size)
        for (sig in signatures) buf += sig
        buf += message
        return buf.toByteArray()
    }

    fun findPda(seeds: List<ByteArray>, programId: ByteArray): ByteArray {
        for (bump in 255 downTo 0) {
            val candidate = createProgramAddress(seeds + listOf(byteArrayOf(bump.toByte())), programId)
            if (candidate != null) return candidate
        }
        throw IllegalStateException("Could not find valid PDA")
    }

    private fun createProgramAddress(seeds: List<ByteArray>, programId: ByteArray): ByteArray? {
        val digest = MessageDigest.getInstance("SHA-256")
        for (seed in seeds) digest.update(seed)
        digest.update(programId)
        digest.update("ProgramDerivedAddress".toByteArray(Charsets.UTF_8))
        val hash = digest.digest()
        return if (isOnCurve(hash)) null else hash
    }

    private fun isOnCurve(point: ByteArray): Boolean = try {
        org.bouncycastle.crypto.params.Ed25519PublicKeyParameters(point)
        true
    } catch (_: Exception) { false }

    private fun writeCompactU16(buf: MutableList<Byte>, value: Int) {
        var v = value
        do {
            var lo = v and 0x7F
            v = v ushr 7
            if (v != 0) lo = lo or 0x80
            buf.add(lo.toByte())
        } while (v != 0)
    }

    private operator fun MutableList<Byte>.plusAssign(b: Byte)       { add(b) }
    private operator fun MutableList<Byte>.plusAssign(arr: ByteArray) { addAll(arr.toList()) }
}
