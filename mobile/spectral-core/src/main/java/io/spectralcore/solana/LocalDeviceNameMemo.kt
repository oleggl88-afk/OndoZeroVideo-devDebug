package io.spectralcore.solana

private const val LOCAL_DEVICE_NAME_MEMO_PREFIX = "ondozero_local_device_name_v1:"

fun buildLocalDeviceNameMemo(localDeviceName: String): String =
    LOCAL_DEVICE_NAME_MEMO_PREFIX + localDeviceName

fun decodeLocalDeviceNameMemo(memo: String): String? =
    memo.takeIf { it.startsWith(LOCAL_DEVICE_NAME_MEMO_PREFIX) }
        ?.removePrefix(LOCAL_DEVICE_NAME_MEMO_PREFIX)