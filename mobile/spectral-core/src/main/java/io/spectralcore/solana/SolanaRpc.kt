package io.spectralcore.solana

import android.util.Log
import io.spectralcore.Base58
import org.json.JSONObject
import java.io.OutputStreamWriter
import java.math.BigInteger
import java.net.HttpURLConnection
import java.net.URL
import kotlin.system.measureTimeMillis

/**
 * Low-level Solana JSON-RPC HTTP client.
 * Responsible only for network I/O — no business logic.
 */
object SolanaRpc {

    private const val TAG = "SolanaRpc"
    private val MEMO_PROGRAM_B58 = Base58.encode(MEMO_PROGRAM)

    fun getLatestBlockhash(rpcUrl: String): String {
        val resp = post(rpcUrl,
            """{"jsonrpc":"2.0","id":1,"method":"getLatestBlockhash","params":[{"commitment":"confirmed"}]}""")
        return JSONObject(resp)
            .getJSONObject("result")
            .getJSONObject("value")
            .getString("blockhash")
    }

    fun sendTransaction(rpcUrl: String, txBase64: String): String {
        val payload = """{"jsonrpc":"2.0","id":1,"method":"sendTransaction","params":["$txBase64",{"encoding":"base64","preflightCommitment":"confirmed"}]}"""
        val resp = post(rpcUrl, payload)
        val obj  = JSONObject(resp)
        if (obj.has("error")) {
            val err = obj.getJSONObject("error")
            throw RuntimeException(
                "RPC error ${err.optInt("code")}: ${err.optString("message")}\n${err.optJSONObject("data") ?: ""}")
        }
        return obj.getString("result")
    }

    fun confirmSignature(rpcUrl: String, signature: String, timeoutMs: Long = 15_000L, pollIntervalMs: Long = 150L): Double {
        val startedAt = System.nanoTime()
        val deadline = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() <= deadline) {
            val payload = """{"jsonrpc":"2.0","id":1,"method":"getSignatureStatuses","params":[["$signature"],{"searchTransactionHistory":true}]}"""
            val resp = post(rpcUrl, payload)
            val obj = JSONObject(resp)
            if (obj.has("error")) {
                throw RuntimeException("getSignatureStatuses error: ${obj.getJSONObject("error")}")
            }
            val values = obj.getJSONObject("result").getJSONArray("value")
            val status = if (values.length() > 0 && !values.isNull(0)) values.getJSONObject(0) else null
            if (status != null) {
                if (!status.isNull("err")) {
                    throw RuntimeException("Transaction $signature failed: ${status.get("err")}")
                }
                val confirmationStatus = status.optString("confirmationStatus", "")
                if (confirmationStatus == "confirmed" || confirmationStatus == "finalized") {
                    return (System.nanoTime() - startedAt) / 1_000_000.0
                }
            }
            Thread.sleep(pollIntervalMs)
        }
        throw RuntimeException("Transaction $signature was not confirmed within ${timeoutMs}ms")
    }

    fun getAccountData(rpcUrl: String, addressB58: String): ByteArray {
        val payload = """{"jsonrpc":"2.0","id":1,"method":"getAccountInfo","params":["$addressB58",{"encoding":"base64","commitment":"confirmed"}]}"""
        val resp  = post(rpcUrl, payload)
        val obj   = JSONObject(resp)
        if (obj.has("error")) throw RuntimeException(
            "getAccountInfo error: ${obj.getJSONObject("error")}")
        val value = obj.getJSONObject("result").optJSONObject("value")
            ?: throw RuntimeException("Account $addressB58 not found on chain")
        return android.util.Base64.decode(
            value.getJSONArray("data").getString(0), android.util.Base64.DEFAULT)
    }

    fun fetchSolBalance(rpcUrl: String, pubkeyBase58: String): Double? {
        return try {
            val body = """{"jsonrpc":"2.0","id":1,"method":"getBalance","params":["$pubkeyBase58",{"commitment":"confirmed"}]}"""
            val lamports = JSONObject(post(rpcUrl, body)).getJSONObject("result").getLong("value")
            lamports / 1_000_000_000.0
        } catch (e: Exception) {
            Log.e(TAG, "fetchSolBalance failed", e)
            null
        }
    }

    fun fetchTokenBalance(rpcUrl: String, ownerBase58: String, mintBase58: String): Long? {
        return try {
            val body = """{"jsonrpc":"2.0","id":1,"method":"getTokenAccountsByOwner","params":["$ownerBase58",{"mint":"$mintBase58"},{"encoding":"jsonParsed","commitment":"confirmed"}]}"""
            val values = JSONObject(post(rpcUrl, body)).getJSONObject("result").getJSONArray("value")
            var total = BigInteger.ZERO
            for (i in 0 until values.length()) {
                val amountText = values.getJSONObject(i)
                    .getJSONObject("account")
                    .getJSONObject("data")
                    .getJSONObject("parsed")
                    .getJSONObject("info")
                    .getJSONObject("tokenAmount")
                    .getString("amount")
                total = total.add(amountText.toBigIntegerOrNull() ?: BigInteger.ZERO)
            }
            total.min(BigInteger.valueOf(Long.MAX_VALUE)).toLong()
        } catch (e: Exception) {
            Log.e(TAG, "fetchTokenBalance failed", e)
            null
        }
    }

    fun fetchTokenMetadataName(rpcUrl: String, mintBase58: String): String? {
        return try {
            val body = """{"jsonrpc":"2.0","id":1,"method":"getAccountInfo","params":["$mintBase58",{"encoding":"jsonParsed","commitment":"confirmed"}]}"""
            val value = JSONObject(post(rpcUrl, body))
                .getJSONObject("result")
                .optJSONObject("value")
                ?: return null
            val extensions = value
                .optJSONObject("data")
                ?.optJSONObject("parsed")
                ?.optJSONObject("info")
                ?.optJSONArray("extensions")
                ?: return null

            for (i in 0 until extensions.length()) {
                val extension = extensions.optJSONObject(i) ?: continue
                if (extension.optString("extension") != "tokenMetadata") continue
                val state = extension.optJSONObject("state") ?: continue
                val name = state.optString("name").trim()
                if (name.isNotEmpty()) return name
                val symbol = state.optString("symbol").trim()
                if (symbol.isNotEmpty()) return symbol
            }
            null
        } catch (e: Exception) {
            Log.e(TAG, "fetchTokenMetadataName failed", e)
            null
        }
    }

    fun fetchSignaturesForAddress(rpcUrl: String, addressB58: String, limit: Int = 10): List<AddressSignatureInfo> {
        return try {
            val body = """{"jsonrpc":"2.0","id":1,"method":"getSignaturesForAddress","params":["$addressB58",{"limit":$limit,"commitment":"confirmed"}]}"""
            val values = JSONObject(post(rpcUrl, body)).getJSONArray("result")
            buildList {
                for (i in 0 until values.length()) {
                    val item = values.getJSONObject(i)
                    add(
                        AddressSignatureInfo(
                            signature = item.getString("signature"),
                            blockTime = if (item.isNull("blockTime")) null else item.getLong("blockTime")
                        )
                    )
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "fetchSignaturesForAddress failed", e)
            emptyList()
        }
    }

    fun fetchTransactionMemo(rpcUrl: String, signature: String): TransactionMemoInfo? {
        return try {
            val body = """{"jsonrpc":"2.0","id":1,"method":"getTransaction","params":["$signature",{"encoding":"jsonParsed","commitment":"confirmed","maxSupportedTransactionVersion":0}]}"""
            val obj = JSONObject(post(rpcUrl, body))
            if (obj.has("error")) {
                throw RuntimeException("getTransaction error: ${obj.getJSONObject("error")}")
            }
            val result = obj.optJSONObject("result") ?: return null
            val blockTime = if (result.isNull("blockTime")) null else result.getLong("blockTime")
            val instructions = result
                .getJSONObject("transaction")
                .getJSONObject("message")
                .getJSONArray("instructions")
            TransactionMemoInfo(
                signature = signature,
                blockTime = blockTime,
                memo = extractMemoFromInstructions(instructions)
            )
        } catch (e: Exception) {
            Log.e(TAG, "fetchTransactionMemo failed", e)
            null
        }
    }

    fun fetchFirstMemoForAddress(rpcUrl: String, addressB58: String, limit: Int = 10): TransactionMemoInfo? {
        val signatures = fetchSignaturesForAddress(rpcUrl, addressB58, limit)
        for (signature in signatures) {
            val tx = fetchTransactionMemo(rpcUrl, signature.signature) ?: continue
            if (!tx.memo.isNullOrEmpty()) return tx
        }
        return null
    }

    private fun extractMemoFromInstructions(instructions: org.json.JSONArray): String? {
        for (i in 0 until instructions.length()) {
            val instruction = instructions.optJSONObject(i) ?: continue
            val programId = instruction.optString("programId")
            val program = instruction.optString("program")
            val isMemoInstruction = programId == MEMO_PROGRAM_B58 ||
                program.equals("spl-memo", ignoreCase = true) ||
                program.equals("memo", ignoreCase = true)
            if (!isMemoInstruction) continue

            val parsed = instruction.opt("parsed")
            when (parsed) {
                is String -> if (parsed.isNotEmpty()) return parsed
                is JSONObject -> {
                    parsed.optString("memo").takeIf { it.isNotEmpty() }?.let { return it }
                    parsed.optString("value").takeIf { it.isNotEmpty() }?.let { return it }
                    parsed.optString("text").takeIf { it.isNotEmpty() }?.let { return it }
                }
            }

            val data = instruction.optString("data")
            if (data.isNotEmpty()) {
                runCatching { String(Base58.decode(data), Charsets.UTF_8) }
                    .getOrNull()
                    ?.takeIf { it.isNotEmpty() }
                    ?.let { return it }
            }
        }
        return null
    }

    fun post(url: String, body: String): String {
        val conn = URL(url).openConnection() as HttpURLConnection
        conn.requestMethod = "POST"
        conn.doOutput = true
        conn.setRequestProperty("Content-Type", "application/json")
        conn.connectTimeout = 15_000
        conn.readTimeout    = 15_000
        OutputStreamWriter(conn.outputStream, Charsets.UTF_8).use { it.write(body) }
        val code = conn.responseCode
        val text = if (code in 200..299)
            conn.inputStream.bufferedReader(Charsets.UTF_8).readText()
        else
            conn.errorStream?.bufferedReader(Charsets.UTF_8)?.readText() ?: "(empty)"
        conn.disconnect()
        Log.d(TAG, "RPC $code: ${text.take(300)}")
        return text
    }
}
