package io.spectralcore

import android.util.Log

/** Bitcoin/Solana compatible Base58 encoder/decoder. */
object Base58 {
    private const val TAG      = "SpectralBase58"
    private const val ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    private const val BASE     = 58

    fun encode(input: ByteArray): String {
        var leadZeros = 0
        for (b in input) { if (b == 0.toByte()) leadZeros++ else break }

        val maxLen = input.size * 138 / 100 + 1
        val digits = IntArray(maxLen)
        var outputLen = 0

        for (i in leadZeros until input.size) {
            var carry = input[i].toInt() and 0xFF
            var j = 0
            while (j < outputLen || carry != 0) {
                carry += 256 * digits[j]
                digits[j] = carry % BASE
                carry /= BASE
                j++
            }
            outputLen = j
        }
        return buildString {
            repeat(leadZeros) { append('1') }
            for (k in outputLen - 1 downTo 0) append(ALPHABET[digits[k]])
        }
    }

    fun decode(input: String): ByteArray {
        val map = IntArray(128) { -1 }
        ALPHABET.forEachIndexed { i, c -> map[c.code] = i }

        var leadZeros = 0
        for (c in input) { if (c == '1') leadZeros++ else break }

        // Output buffer: ceil(inputLen * log(58)/log(256)) + 1 safety margin.
        // log(58)/log(256) ≈ 0.733, so maxLen covers the decoded byte length.
        val maxLen = (input.length - leadZeros) * 733 / 1000 + 2
        val bytes  = IntArray(maxLen)
        var outputLen = 0

        for (i in leadZeros until input.length) {
            val c   = input[i]
            val idx = if (c.code < map.size) map[c.code] else -1
            if (idx < 0) throw IllegalArgumentException("Invalid Base58 character: '$c'")
            var carry = idx
            var j = 0
            // Multiply accumulated big-integer by 58 (input base) and add new digit,
            // then reduce to base-256 bytes. carry /= 256 (NOT /= BASE) because we are
            // converting TO byte representation.
            while (j < outputLen || carry != 0) {
                carry += BASE * bytes[j]
                bytes[j] = carry % 256
                carry /= 256
                j++
            }
            outputLen = j
        }
        Log.d(TAG, "decode(\"${input.take(12)}…\") leadZeros=$leadZeros outputLen=$outputLen")
        val result = ByteArray(leadZeros + outputLen)
        for (k in 0 until outputLen) result[leadZeros + k] = bytes[outputLen - 1 - k].toByte()
        return result
    }
}
