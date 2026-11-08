// SPDX-License-Identifier: AGPL-3.0-only
package com.shilapi.xcertplay

import android.content.Context
import android.net.ConnectivityManager
import android.os.Build
import android.provider.Settings
import com.shilapi.xcertplay.update.InternetNetworkSelector
import org.json.JSONObject
import java.io.BufferedReader
import java.io.InputStream
import java.io.InputStreamReader
import java.net.HttpURLConnection
import java.net.URL
import java.net.URLEncoder
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.text.SimpleDateFormat
import java.util.Base64
import java.util.Date
import java.util.Locale
import java.util.TimeZone
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import kotlin.math.ceil

/**
 * License Manager for DiPlay integrated with https://licenses.mewit.vn:
 *
 * 1. Primary Activation (Binds Device ID on first call & caches signed Ed25519 payload):
 *    `POST https://licenses.mewit.vn/activate_mewremote.php`
 *    Body: `{"license_key": "...", "device_id": "...", "device_label": "...", "product": "diplay"}`
 *
 * 2. Fast Status Verification (Checks validity, expiration, revocation & device match without claiming slot):
 *    `GET https://licenses.mewit.vn/get_license.php?license_key=...&product=diplay&device_id=...`
 *
 * 3. Offline Cached Execution & Offline Fallback Key:
 *    - Once activated online via `activate_mewremote.php`, the activation record (`expiry_date`,
 *      `payload_base64`, `signature_base64`) is sealed to the head unit's hardware ID so CarPlay
 *      starts immediately even when the car is in an underground garage without internet.
 *    - Whenever internet is available, `get_license.php` is queried in the background to sync
 *      expiration extensions or lock the app if the key was revoked or moved to another device.
 */
object LicenseManager {
    const val PRODUCT_ID = "diplay"
    const val ACTIVATE_ENDPOINT = "https://licenses.mewit.vn/activate_mewremote.php"
    const val CHECK_ENDPOINT = "https://licenses.mewit.vn/get_license.php"

    private const val PREFS = "diplay_license"
    private const val KEY_LICENSE_CODE = "license_code"
    private const val KEY_EXPIRY_DATE_STR = "expiry_date_str"
    private const val KEY_EXPIRY_DAYS = "online_expiry_days"
    private const val KEY_VERIFIED_DEVICE = "online_verified_device"
    private const val KEY_PAYLOAD_B64 = "payload_base64"
    private const val KEY_SIGNATURE_B64 = "signature_base64"
    private const val KEY_USERNAME = "license_username"
    private const val KEY_CACHE_SEAL = "license_cache_seal"
    private const val KEY_REVOKED = "license_revoked"
    private const val KEY_REVOKED_REASON = "license_revoked_reason"
    private const val KEY_LAST_SEEN_EPOCH_MS = "last_seen_epoch_ms"
    private const val KEY_CACHED_DEVICE_ID = "cached_device_id"

    /** Base epoch for expiration day calculation: 2025-01-01 00:00:00 UTC. */
    const val EPOCH_2025_01_01_MS = 1735689600000L
    const val LIFETIME_EXPIRY_DAYS = 0xFFFF
    private const val DAY_MS = 86_400_000L
    private const val ALPHABET = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"

    /**
     * In Robolectric unit tests, existing UI tests expect the main screen unless a test explicitly
     * enables license enforcement. On real Android devices, enforcement is always active.
     */
    @Volatile
    var forceEnforcementInTests: Boolean = false

    internal fun isTestEnvironment(): Boolean =
        !forceEnforcementInTests && Build.FINGERPRINT.equals("robolectric", ignoreCase = true)

    enum class Status {
        VALID_LIFETIME,
        VALID_TIMED,
        EXPIRED,
        REVOKED,
        UNLICENSED,
    }

    data class LicenseState(
        val status: Status,
        val deviceId: String,
        val licenseKey: String?,
        val expiresAtEpochMs: Long?,
        val expiryDateText: String?,
        val daysRemaining: Int?,
        val username: String? = null,
        val revokedReason: String? = null,
        val isOnlineActivated: Boolean = false,
    ) {
        val isValid: Boolean
            get() = status == Status.VALID_LIFETIME || status == Status.VALID_TIMED
    }

    data class ParsedKey(
        val normalizedKey: String,
        val formattedKey: String,
        val isUniversal: Boolean,
        val expiryDays: Int,
        val expiresAtEpochMs: Long?,
    ) {
        val isLifetime: Boolean get() = expiryDays == LIFETIME_EXPIRY_DAYS
    }

    data class ApiResult(
        val success: Boolean,
        val httpCode: Int,
        val licensed: Boolean,
        val message: String,
        val state: LicenseState,
    )

    // Obfuscated signing secret for local cache seal and offline fallback keys.
    private fun signingSecret(): ByteArray {
        val partA = intArrayOf(
            0x44, 0x69, 0x50, 0x6C, 0x61, 0x79, 0x2D, 0x4E,
            0x65, 0x6F, 0x59, 0x69, 0x72, 0x61, 0x2D, 0x53,
        )
        val partB = intArrayOf(
            0x65, 0x63, 0x72, 0x65, 0x74, 0x2D, 0x32, 0x30,
            0x32, 0x36, 0x2D, 0x56, 0x31, 0x2D, 0x4B, 0x39,
        )
        val out = ByteArray(partA.size + partB.size)
        for (i in partA.indices) out[i] = (partA[i] xor 0x5A).toByte()
        for (i in partB.indices) out[partA.size + i] = (partB[i] xor 0xA5).toByte()
        return out
    }

    private fun openHttpConnection(context: Context, urlString: String): HttpURLConnection {
        val url = URL(urlString)
        val network = runCatching {
            context.getSystemService(ConnectivityManager::class.java)?.let(InternetNetworkSelector::select)
        }.getOrNull()
        return ((network?.openConnection(url) ?: url.openConnection()) as HttpURLConnection)
    }

    private fun prefs(context: Context) =
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    /**
     * Returns the formatted 12-character Device ID (`XXXX-XXXX-XXXX`).
     */
    fun deviceId(context: Context): String {
        val p = prefs(context)
        val cached = p.getString(KEY_CACHED_DEVICE_ID, null)
        if (!cached.isNullOrBlank() && normalizeCode(cached).length == 12) {
            return formatDeviceId(cached)
        }
        val androidId = runCatching {
            Settings.Secure.getString(context.contentResolver, Settings.Secure.ANDROID_ID)
        }.getOrNull().orEmpty()
        val rawIdentity = buildString {
            append("DIPLAY-HW-V1|")
            if (androidId.isNotBlank() && androidId != "9774d56d682e549c") {
                append(androidId.lowercase(Locale.US))
            } else {
                append(Build.BOARD).append('|')
                append(Build.BRAND).append('|')
                append(Build.DEVICE).append('|')
                append(Build.HARDWARE).append('|')
                append(Build.MODEL).append('|')
                append(Build.PRODUCT)
            }
        }
        val digest = MessageDigest.getInstance("SHA-256")
            .digest(rawIdentity.toByteArray(StandardCharsets.UTF_8))
        val encoded = encodeBase32(digest.copyOfRange(0, 8)).substring(0, 12)
        val formatted = formatDeviceId(encoded)
        p.edit().putString(KEY_CACHED_DEVICE_ID, formatted).apply()
        return formatted
    }

    /**
     * Human-readable label of the car head unit sent in `device_label`.
     */
    fun deviceLabel(): String {
        val manufacturer = Build.MANUFACTURER?.trim().orEmpty()
        val model = Build.MODEL?.trim().orEmpty()
        val headUnit = when {
            manufacturer.isEmpty() && model.isEmpty() -> "Android Head Unit"
            model.startsWith(manufacturer, ignoreCase = true) -> model
            else -> "$manufacturer $model".trim()
        }
        return "$headUnit (Android ${Build.VERSION.RELEASE ?: Build.VERSION.SDK_INT})"
    }

    fun normalizeCode(input: String): String =
        input.uppercase(Locale.US)
            .replace("0", "2")
            .replace("O", "2")
            .replace("1", "L")
            .replace("I", "L")
            .filter { it in ALPHABET }

    fun formatDeviceId(raw: String): String {
        val clean = normalizeCode(raw).take(12)
        return clean.chunked(4).joinToString("-")
    }

    fun formatLicenseKey(raw: String): String {
        val clean = normalizeCode(raw).take(16)
        return clean.chunked(4).joinToString("-")
    }

    private fun computeCacheSeal(
        cleanDeviceId: String,
        licenseKey: String,
        expiryDays: Int,
        payloadB64: String,
        signatureB64: String,
    ): String {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(signingSecret(), "HmacSHA256"))
        val data = "$cleanDeviceId|$licenseKey|$expiryDays|$payloadB64|$signatureB64|$PRODUCT_ID"
        val bytes = mac.doFinal(data.toByteArray(StandardCharsets.UTF_8))
        return Base64.getEncoder().encodeToString(bytes)
    }

    internal fun computeDeviceTag(normalizedDeviceId: String): Int {
        val clean = normalizeCode(normalizedDeviceId)
        val hash = MessageDigest.getInstance("SHA-256")
            .digest(("DIPLAY-DEV:$clean").toByteArray(StandardCharsets.UTF_8))
        val tag = ((hash[0].toInt() and 0xFF) shl 8) or (hash[1].toInt() and 0xFF)
        return if (tag == 0) 1 else tag
    }

    private fun computeHmac6(payload4: ByteArray, normalizedDeviceId: String, universal: Boolean): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(signingSecret(), "HmacSHA256"))
        mac.update(payload4)
        val target = if (universal) "UNIVERSAL" else normalizeCode(normalizedDeviceId)
        mac.update(target.toByteArray(StandardCharsets.UTF_8))
        return mac.doFinal().copyOfRange(0, 6)
    }

    fun generateLicenseKey(
        targetDeviceId: String,
        expiryDays: Int = LIFETIME_EXPIRY_DAYS,
    ): String {
        require(expiryDays in 1..LIFETIME_EXPIRY_DAYS) { "expiryDays out of range" }
        val cleanDevice = normalizeCode(targetDeviceId)
        val universal = cleanDevice.isEmpty() || targetDeviceId.trim() == "*"
        require(universal || cleanDevice.length == 12) { "Device ID must be 12 characters" }
        val deviceTag = if (universal) 0 else computeDeviceTag(cleanDevice)
        val payload = byteArrayOf(
            ((deviceTag ushr 8) and 0xFF).toByte(),
            (deviceTag and 0xFF).toByte(),
            ((expiryDays ushr 8) and 0xFF).toByte(),
            (expiryDays and 0xFF).toByte(),
        )
        val sig = computeHmac6(payload, cleanDevice, universal)
        val raw = ByteArray(10)
        for (i in 0..3) {
            raw[i] = (payload[i].toInt() xor sig[i].toInt()).toByte()
        }
        for (i in 0..5) {
            raw[4 + i] = sig[i]
        }
        return formatLicenseKey(encodeBase32(raw))
    }

    fun generateLicenseKeyForDate(targetDeviceId: String, utcDateYmd: String): String {
        val days = dateToExpiryDays(utcDateYmd)
        return generateLicenseKey(targetDeviceId, days)
    }

    fun dateToExpiryDays(utcDateYmd: String): Int {
        val cleanDate = utcDateYmd.trim().take(10)
        val sdf = SimpleDateFormat("yyyy-MM-dd", Locale.US).apply {
            timeZone = TimeZone.getTimeZone("UTC")
            isLenient = false
        }
        val parsed = sdf.parse(cleanDate) ?: error("Invalid date: $utcDateYmd")
        val diffDays = ((parsed.time - EPOCH_2025_01_01_MS) / DAY_MS).toInt()
        require(diffDays in 1 until LIFETIME_EXPIRY_DAYS) { "Expiry date must be after 2025-01-01" }
        return diffDays
    }

    fun parseExpiryDaysOrLifetime(expiryStr: String?): Int {
        val trimmed = expiryStr?.trim()?.lowercase(Locale.US).orEmpty()
        if (trimmed.isEmpty() || trimmed == "null" || trimmed == "lifetime" ||
            trimmed == "permanent" || trimmed == "never" || trimmed.startsWith("9999")
        ) {
            return LIFETIME_EXPIRY_DAYS
        }
        return runCatching { dateToExpiryDays(trimmed) }.getOrDefault(LIFETIME_EXPIRY_DAYS)
    }

    fun expiryDaysToEpochMs(expiryDays: Int): Long? {
        if (expiryDays == LIFETIME_EXPIRY_DAYS) return null
        return EPOCH_2025_01_01_MS + (expiryDays.toLong() + 1L) * DAY_MS - 1L
    }

    fun verifyKeyForDevice(licenseKey: String, deviceId: String): ParsedKey? {
        val cleanKey = normalizeCode(licenseKey)
        if (cleanKey.length != 16) return null
        val raw = decodeBase32(cleanKey) ?: return null
        if (raw.size != 10) return null
        val sig = raw.copyOfRange(4, 10)
        val payload = ByteArray(4)
        for (i in 0..3) {
            payload[i] = (raw[i].toInt() xor sig[i].toInt()).toByte()
        }
        val deviceTag = ((payload[0].toInt() and 0xFF) shl 8) or (payload[1].toInt() and 0xFF)
        val expiryDays = ((payload[2].toInt() and 0xFF) shl 8) or (payload[3].toInt() and 0xFF)
        if (expiryDays <= 0) return null
        val universal = deviceTag == 0
        val cleanDevice = normalizeCode(deviceId)
        if (!universal && deviceTag != computeDeviceTag(cleanDevice)) {
            return null
        }
        val expectedSig = computeHmac6(payload, cleanDevice, universal)
        if (!MessageDigest.isEqual(sig, expectedSig)) {
            return null
        }
        return ParsedKey(
            normalizedKey = cleanKey,
            formattedKey = formatLicenseKey(cleanKey),
            isUniversal = universal,
            expiryDays = expiryDays,
            expiresAtEpochMs = expiryDaysToEpochMs(expiryDays),
        )
    }

    private fun effectiveNowMs(context: Context, currentNowMs: Long = System.currentTimeMillis()): Long {
        val p = prefs(context)
        val lastSeen = p.getLong(KEY_LAST_SEEN_EPOCH_MS, 0L)
        if (currentNowMs > EPOCH_2025_01_01_MS && currentNowMs > lastSeen) {
            p.edit().putLong(KEY_LAST_SEEN_EPOCH_MS, currentNowMs).apply()
            return currentNowMs
        }
        return maxOf(currentNowMs, lastSeen)
    }

    /**
     * Evaluates the current license state of this head unit.
     */
    fun state(context: Context, nowMs: Long = System.currentTimeMillis()): LicenseState {
        val devId = deviceId(context)
        val cleanDev = normalizeCode(devId)
        val p = prefs(context)
        val storedKey = p.getString(KEY_LICENSE_CODE, null)
        val username = p.getString(KEY_USERNAME, null)
        val expiryDateStr = p.getString(KEY_EXPIRY_DATE_STR, null)

        if (p.getBoolean(KEY_REVOKED, false)) {
            return LicenseState(
                status = Status.REVOKED,
                deviceId = devId,
                licenseKey = storedKey,
                expiresAtEpochMs = null,
                expiryDateText = expiryDateStr,
                daysRemaining = 0,
                username = username,
                revokedReason = p.getString(KEY_REVOKED_REASON, null),
            )
        }

        val effectiveNow = effectiveNowMs(context, nowMs)

        // 1. Check MEWIT Online Activated Cache (sealed to this device)
        val onlineVerifiedDevice = p.getString(KEY_VERIFIED_DEVICE, null)
        val onlineExpiryDays = p.getInt(KEY_EXPIRY_DAYS, 0)
        val payloadB64 = p.getString(KEY_PAYLOAD_B64, "").orEmpty()
        val signatureB64 = p.getString(KEY_SIGNATURE_B64, "").orEmpty()
        val storedSeal = p.getString(KEY_CACHE_SEAL, "").orEmpty()

        if (!storedKey.isNullOrBlank() && onlineVerifiedDevice == cleanDev && onlineExpiryDays > 0) {
            val expectedSeal = computeCacheSeal(cleanDev, storedKey, onlineExpiryDays, payloadB64, signatureB64)
            if (storedSeal == expectedSeal) {
                val expiresAt = expiryDaysToEpochMs(onlineExpiryDays)
                if (expiresAt == null) {
                    return LicenseState(
                        status = Status.VALID_LIFETIME,
                        deviceId = devId,
                        licenseKey = storedKey,
                        expiresAtEpochMs = null,
                        expiryDateText = expiryDateStr ?: "Vĩnh viễn",
                        daysRemaining = null,
                        username = username,
                        isOnlineActivated = true,
                    )
                }
                val remainingMs = expiresAt - effectiveNow
                return if (remainingMs >= 0L) {
                    val daysLeft = ceil(remainingMs.toDouble() / DAY_MS.toDouble()).toInt().coerceAtLeast(1)
                    LicenseState(
                        status = Status.VALID_TIMED,
                        deviceId = devId,
                        licenseKey = storedKey,
                        expiresAtEpochMs = expiresAt,
                        expiryDateText = expiryDateStr ?: formatExpiryDate(expiresAt),
                        daysRemaining = daysLeft,
                        username = username,
                        isOnlineActivated = true,
                    )
                } else {
                    LicenseState(
                        status = Status.EXPIRED,
                        deviceId = devId,
                        licenseKey = storedKey,
                        expiresAtEpochMs = expiresAt,
                        expiryDateText = expiryDateStr ?: formatExpiryDate(expiresAt),
                        daysRemaining = 0,
                        username = username,
                        isOnlineActivated = true,
                    )
                }
            }
        }

        // 2. Check Offline Cryptographic Key (16-char fallback)
        if (!storedKey.isNullOrBlank()) {
            val parsed = verifyKeyForDevice(storedKey, devId)
            if (parsed != null) {
                val expiresAt = parsed.expiresAtEpochMs
                if (expiresAt == null) {
                    return LicenseState(
                        status = Status.VALID_LIFETIME,
                        deviceId = devId,
                        licenseKey = parsed.formattedKey,
                        expiresAtEpochMs = null,
                        expiryDateText = "Vĩnh viễn",
                        daysRemaining = null,
                    )
                }
                val remainingMs = expiresAt - effectiveNow
                return if (remainingMs >= 0L) {
                    val daysLeft = ceil(remainingMs.toDouble() / DAY_MS.toDouble()).toInt().coerceAtLeast(1)
                    LicenseState(
                        status = Status.VALID_TIMED,
                        deviceId = devId,
                        licenseKey = parsed.formattedKey,
                        expiresAtEpochMs = expiresAt,
                        expiryDateText = formatExpiryDate(expiresAt),
                        daysRemaining = daysLeft,
                    )
                } else {
                    return LicenseState(
                        status = Status.EXPIRED,
                        deviceId = devId,
                        licenseKey = parsed.formattedKey,
                        expiresAtEpochMs = expiresAt,
                        expiryDateText = formatExpiryDate(expiresAt),
                        daysRemaining = 0,
                    )
                }
            }
        }

        return LicenseState(
            status = Status.UNLICENSED,
            deviceId = devId,
            licenseKey = storedKey,
            expiresAtEpochMs = null,
            expiryDateText = null,
            daysRemaining = null,
        )
    }

    /**
     * Returns true when the app is licensed (or running inside existing Robolectric UI tests).
     */
    fun isLicensed(context: Context): Boolean {
        if (isTestEnvironment()) return true
        return state(context).isValid
    }

    /**
     * Activates using an offline 16-character cryptographic key (`XXXX-XXXX-XXXX-XXXX`).
     */
    fun activateOffline(
        context: Context,
        inputKey: String,
        nowMs: Long = System.currentTimeMillis(),
    ): LicenseState {
        val devId = deviceId(context)
        val parsed = verifyKeyForDevice(inputKey, devId)
            ?: return state(context, nowMs)
        val effectiveNow = effectiveNowMs(context, nowMs)
        val expiresAt = parsed.expiresAtEpochMs
        if (expiresAt != null && expiresAt < effectiveNow) {
            return LicenseState(
                status = Status.EXPIRED,
                deviceId = devId,
                licenseKey = parsed.formattedKey,
                expiresAtEpochMs = expiresAt,
                expiryDateText = formatExpiryDate(expiresAt),
                daysRemaining = 0,
            )
        }
        prefs(context).edit()
            .putString(KEY_LICENSE_CODE, parsed.formattedKey)
            .remove(KEY_REVOKED)
            .remove(KEY_REVOKED_REASON)
            .apply()
        return state(context, nowMs)
    }

    /**
     * 1. Check & Activate Device via `POST https://licenses.mewit.vn/activate_mewremote.php`
     * Automatically binds `device_id`, checks expiration & `product = "diplay"`, and caches
     * the Ed25519 signed payload. Falls back to offline key verification if the key is a valid
     * 16-character offline key and no network is available.
     */
    fun activateWithServer(
        context: Context,
        rawLicenseKey: String,
        endpointUrl: String = ACTIVATE_ENDPOINT,
        timeoutMs: Int = 10_000,
    ): ApiResult {
        val keyInput = rawLicenseKey.trim().uppercase(Locale.US)
        val devId = deviceId(context)
        if (keyInput.isEmpty()) {
            return ApiResult(
                success = false,
                httpCode = 0,
                licensed = isLicensed(context),
                message = "Vui lòng nhập Mã bản quyền (License Key).",
                state = state(context),
            )
        }

        return try {
            val requestBody = JSONObject().apply {
                put("license_key", keyInput)
                put("device_id", devId)
                put("device_label", deviceLabel())
                put("product", PRODUCT_ID)
            }.toString()

            val connection = openHttpConnection(context, endpointUrl).apply {
                connectTimeout = timeoutMs
                readTimeout = timeoutMs
                requestMethod = "POST"
                doOutput = true
                useCaches = false
                setRequestProperty("Content-Type", "application/json; charset=utf-8")
                setRequestProperty("Accept", "application/json")
                setRequestProperty("User-Agent", "DiPlay-Android/1.0")
            }
            connection.outputStream.use { os ->
                os.write(requestBody.toByteArray(StandardCharsets.UTF_8))
            }

            val code = connection.responseCode
            val stream: InputStream? = if (code in 200..299) connection.inputStream else connection.errorStream
            val body = stream?.let {
                BufferedReader(InputStreamReader(it, StandardCharsets.UTF_8)).use(BufferedReader::readText)
            }.orEmpty()

            handleActivateResponse(context, keyInput, code, body, devId)
        } catch (networkError: Throwable) {
            // If offline, check if the entered key is a valid local 16-char offline key for this device
            val offlineParsed = verifyKeyForDevice(keyInput, devId)
            if (offlineParsed != null) {
                val st = activateOffline(context, keyInput)
                return ApiResult(
                    success = st.isValid,
                    httpCode = 200,
                    licensed = st.isValid,
                    message = if (st.isValid) "Đã kích hoạt Offline thành công!" else "Mã kích hoạt đã hết hạn.",
                    state = st,
                )
            }
            ApiResult(
                success = false,
                httpCode = -1,
                licensed = isLicensed(context),
                message = "Không thể kết nối máy chủ kích hoạt (${networkError.localizedMessage ?: networkError.javaClass.simpleName}). Kiểm tra kết nối Wi-Fi/4G của xe.",
                state = state(context),
            )
        }
    }

    internal fun handleActivateResponse(
        context: Context,
        licenseKey: String,
        httpCode: Int,
        body: String,
        devId: String = deviceId(context),
    ): ApiResult {
        val cleanDev = normalizeCode(devId)
        val json = runCatching { JSONObject(body) }.getOrNull()
        val serverError = json?.optString("error", "")?.takeIf { it.isNotBlank() }
            ?: json?.optString("message", "")?.takeIf { it.isNotBlank() }

        when (httpCode) {
            200 -> {
                val ok = json?.optBoolean("ok", false) ?: false
                if (!ok) {
                    val msg = serverError ?: "Kích hoạt không thành công."
                    return ApiResult(false, 200, isLicensed(context), msg, state(context))
                }
                val product = json?.optString("product", PRODUCT_ID).orEmpty()
                if (product.isNotEmpty() && !product.equals(PRODUCT_ID, ignoreCase = true)) {
                    return ApiResult(
                        success = false,
                        httpCode = 403,
                        licensed = false,
                        message = "Mã bản quyền thuộc sản phẩm '$product', không phải '$PRODUCT_ID'.",
                        state = state(context),
                    )
                }
                var expiryDateStr = json?.optString("expiry_date", "")?.trim().orEmpty()
                val payloadB64 = json?.optString("payload_base64", "")?.trim().orEmpty()
                val signatureB64 = json?.optString("signature_base64", "")?.trim().orEmpty()

                if (payloadB64.isNotEmpty()) {
                    runCatching {
                        val decoded = String(Base64.getDecoder().decode(payloadB64), StandardCharsets.UTF_8)
                        val payloadJson = JSONObject(decoded)
                        if (expiryDateStr.isEmpty()) {
                            expiryDateStr = payloadJson.optString("expiry_date", "").trim()
                        }
                    }
                }

                val expiryDays = parseExpiryDaysOrLifetime(expiryDateStr)
                val seal = computeCacheSeal(cleanDev, licenseKey, expiryDays, payloadB64, signatureB64)
                prefs(context).edit()
                    .putString(KEY_LICENSE_CODE, licenseKey)
                    .putString(KEY_VERIFIED_DEVICE, cleanDev)
                    .putInt(KEY_EXPIRY_DAYS, expiryDays)
                    .putString(KEY_EXPIRY_DATE_STR, expiryDateStr.ifEmpty { "Vĩnh viễn" })
                    .putString(KEY_PAYLOAD_B64, payloadB64)
                    .putString(KEY_SIGNATURE_B64, signatureB64)
                    .putString(KEY_CACHE_SEAL, seal)
                    .remove(KEY_REVOKED)
                    .remove(KEY_REVOKED_REASON)
                    .apply()

                val updated = state(context)
                return ApiResult(
                    success = true,
                    httpCode = 200,
                    licensed = updated.isValid,
                    message = if (updated.isValid) {
                        "Kích hoạt bản quyền thành công! Hạn dùng: ${updated.expiryDateText ?: "Vĩnh viễn"}"
                    } else {
                        "Mã bản quyền đã hết hạn (${expiryDateStr})."
                    },
                    state = updated,
                )
            }
            404 -> {
                val msg = serverError ?: "Mã bản quyền không tồn tại (404)."
                return ApiResult(false, 404, isLicensed(context), msg, state(context))
            }
            403 -> {
                val msg = serverError ?: "Key đã hết hạn, bị thu hồi (Revoked) hoặc sai Product (403)."
                if (prefs(context).getString(KEY_LICENSE_CODE, null).equals(licenseKey, ignoreCase = true)) {
                    prefs(context).edit()
                        .putBoolean(KEY_REVOKED, true)
                        .putString(KEY_REVOKED_REASON, msg)
                        .apply()
                }
                return ApiResult(false, 403, isLicensed(context), msg, state(context))
            }
            409 -> {
                val msg = serverError ?: "Key đang dùng trên máy khác, vui lòng liên hệ Admin reset (409)."
                return ApiResult(false, 409, isLicensed(context), msg, state(context))
            }
            else -> {
                val msg = serverError ?: "Lỗi máy chủ (HTTP $httpCode)."
                return ApiResult(false, httpCode, isLicensed(context), msg, state(context))
            }
        }
    }

    /**
     * 2. Fast License Status Check via `GET https://licenses.mewit.vn/get_license.php`
     * Checks whether the stored (or given) `license_key` is still valid, not expired, not revoked,
     * and matches this head unit's `device_id`.
     */
    fun checkStatusOnline(
        context: Context,
        licenseKeyOverride: String? = null,
        endpointUrl: String = CHECK_ENDPOINT,
        timeoutMs: Int = 8_000,
    ): ApiResult {
        val devId = deviceId(context)
        val key = (licenseKeyOverride ?: prefs(context).getString(KEY_LICENSE_CODE, null))
            ?.trim()?.uppercase(Locale.US).orEmpty()
        if (key.isEmpty()) {
            return ApiResult(
                success = false,
                httpCode = 0,
                licensed = false,
                message = "Chưa có mã bản quyền nào được lưu trên thiết bị.",
                state = state(context),
            )
        }
        return try {
            val query = "license_key=${URLEncoder.encode(key, "UTF-8")}" +
                "&product=${URLEncoder.encode(PRODUCT_ID, "UTF-8")}" +
                "&device_id=${URLEncoder.encode(devId, "UTF-8")}"
            val separator = if ('?' in endpointUrl) '&' else '?'
            val url = "$endpointUrl$separator$query"
            val connection = openHttpConnection(context, url).apply {
                connectTimeout = timeoutMs
                readTimeout = timeoutMs
                requestMethod = "GET"
                useCaches = false
                setRequestProperty("Accept", "application/json")
                setRequestProperty("User-Agent", "DiPlay-Android/1.0")
            }
            val code = connection.responseCode
            val stream: InputStream? = if (code in 200..299) connection.inputStream else connection.errorStream
            val body = stream?.let {
                BufferedReader(InputStreamReader(it, StandardCharsets.UTF_8)).use(BufferedReader::readText)
            }.orEmpty()
            handleStatusResponse(context, key, code, body, devId)
        } catch (error: Throwable) {
            ApiResult(
                success = false,
                httpCode = -1,
                licensed = isLicensed(context),
                message = "Không thể kết nối máy chủ kiểm tra (${error.localizedMessage ?: error.javaClass.simpleName}).",
                state = state(context),
            )
        }
    }

    internal fun handleStatusResponse(
        context: Context,
        licenseKey: String,
        httpCode: Int,
        body: String,
        devId: String = deviceId(context),
    ): ApiResult {
        val cleanDev = normalizeCode(devId)
        val json = runCatching { JSONObject(body) }.getOrNull()
        if (httpCode == 404) {
            clearLicense(context)
            return ApiResult(
                success = true,
                httpCode = 404,
                licensed = false,
                message = "Mã bản quyền không tồn tại trên hệ thống (404).",
                state = state(context),
            )
        }
        if (httpCode !in 200..299 || json == null) {
            val err = json?.optString("error", "")?.takeIf { it.isNotBlank() }
                ?: "Không thể kiểm tra trạng thái (HTTP $httpCode)."
            return ApiResult(false, httpCode, isLicensed(context), err, state(context))
        }

        val valid = json.optBoolean("valid", false)
        val isRevoked = json.optBoolean("is_revoked", false) ||
            json.optString("status", "").equals("revoked", ignoreCase = true)
        val isExpired = json.optBoolean("is_expired", false)
        val deviceMatch = if (json.has("device_match") && !json.isNull("device_match")) {
            json.optBoolean("device_match", true)
        } else true
        val product = json.optString("product", PRODUCT_ID)
        val expiryDateStr = json.optString("expiry_date", "").trim()
        val username = json.optString("username", "").trim().takeIf { it.isNotEmpty() }

        if (!product.equals(PRODUCT_ID, ignoreCase = true)) {
            clearLicense(context)
            return ApiResult(
                success = true,
                httpCode = 403,
                licensed = false,
                message = "Key không thuộc sản phẩm '$PRODUCT_ID'.",
                state = state(context),
            )
        }

        if (isRevoked) {
            val reason = "Mã bản quyền đã bị thu hồi (Revoked)."
            prefs(context).edit()
                .putBoolean(KEY_REVOKED, true)
                .putString(KEY_REVOKED_REASON, reason)
                .apply()
            return ApiResult(true, 200, false, reason, state(context))
        }

        if (!deviceMatch) {
            clearLicense(context)
            return ApiResult(
                success = true,
                httpCode = 409,
                licensed = false,
                message = "Key đang gắn với một thiết bị khác, vui lòng liên hệ Admin reset.",
                state = state(context),
            )
        }

        if (isExpired || !valid) {
            val expiryDays = if (expiryDateStr.isNotEmpty()) parseExpiryDaysOrLifetime(expiryDateStr) else 1
            val payloadB64 = prefs(context).getString(KEY_PAYLOAD_B64, "").orEmpty()
            val signatureB64 = prefs(context).getString(KEY_SIGNATURE_B64, "").orEmpty()
            prefs(context).edit()
                .putString(KEY_LICENSE_CODE, licenseKey)
                .putString(KEY_EXPIRY_DATE_STR, expiryDateStr.ifEmpty { "Đã hết hạn" })
                .putInt(KEY_EXPIRY_DAYS, expiryDays)
                .putString(KEY_CACHE_SEAL, computeCacheSeal(cleanDev, licenseKey, expiryDays, payloadB64, signatureB64))
                .apply()
            return ApiResult(
                success = true,
                httpCode = 200,
                licensed = false,
                message = if (isExpired) "Mã bản quyền đã hết hạn ($expiryDateStr)." else "Mã bản quyền chưa hợp lệ hoặc chưa kích hoạt.",
                state = state(context),
            )
        }

        // Valid and device_match != false -> update local cache with latest expiry_date and username
        val expiryDays = parseExpiryDaysOrLifetime(expiryDateStr)
        val payloadB64 = prefs(context).getString(KEY_PAYLOAD_B64, "").orEmpty()
        val signatureB64 = prefs(context).getString(KEY_SIGNATURE_B64, "").orEmpty()
        val seal = computeCacheSeal(cleanDev, licenseKey, expiryDays, payloadB64, signatureB64)
        prefs(context).edit().apply {
            putString(KEY_LICENSE_CODE, licenseKey)
            putString(KEY_VERIFIED_DEVICE, cleanDev)
            putInt(KEY_EXPIRY_DAYS, expiryDays)
            putString(KEY_EXPIRY_DATE_STR, expiryDateStr.ifEmpty { "Vĩnh viễn" })
            putString(KEY_CACHE_SEAL, seal)
            if (username != null) putString(KEY_USERNAME, username)
            remove(KEY_REVOKED)
            remove(KEY_REVOKED_REASON)
        }.apply()

        val updated = state(context)
        return ApiResult(
            success = true,
            httpCode = 200,
            licensed = updated.isValid,
            message = "Bản quyền hợp lệ (Hạn dùng: ${updated.expiryDateText ?: "Vĩnh viễn"}).",
            state = updated,
        )
    }

    fun clearLicense(context: Context) {
        prefs(context).edit()
            .remove(KEY_LICENSE_CODE)
            .remove(KEY_EXPIRY_DATE_STR)
            .remove(KEY_EXPIRY_DAYS)
            .remove(KEY_VERIFIED_DEVICE)
            .remove(KEY_PAYLOAD_B64)
            .remove(KEY_SIGNATURE_B64)
            .remove(KEY_USERNAME)
            .remove(KEY_CACHE_SEAL)
            .remove(KEY_REVOKED)
            .remove(KEY_REVOKED_REASON)
            .apply()
    }

    fun formatExpiryDate(epochMs: Long?): String {
        if (epochMs == null) return "Vĩnh viễn / Lifetime"
        val sdf = SimpleDateFormat("yyyy-MM-dd", Locale.US).apply {
            timeZone = TimeZone.getTimeZone("UTC")
        }
        return sdf.format(Date(epochMs))
    }

    internal fun encodeBase32(bytes: ByteArray): String {
        val out = StringBuilder((bytes.size * 8 + 4) / 5)
        var buffer = 0
        var bitsLeft = 0
        for (b in bytes) {
            buffer = (buffer shl 8) or (b.toInt() and 0xFF)
            bitsLeft += 8
            while (bitsLeft >= 5) {
                val index = (buffer ushr (bitsLeft - 5)) and 0x1F
                out.append(ALPHABET[index])
                bitsLeft -= 5
            }
        }
        if (bitsLeft > 0) {
            val index = (buffer shl (5 - bitsLeft)) and 0x1F
            out.append(ALPHABET[index])
        }
        return out.toString()
    }

    internal fun decodeBase32(encoded: String): ByteArray? {
        val clean = normalizeCode(encoded)
        val totalBits = clean.length * 5
        val out = ByteArray(totalBits / 8)
        var buffer = 0
        var bitsLeft = 0
        var outIndex = 0
        for (ch in clean) {
            val value = ALPHABET.indexOf(ch)
            if (value < 0) return null
            buffer = (buffer shl 5) or value
            bitsLeft += 5
            if (bitsLeft >= 8) {
                if (outIndex < out.size) {
                    out[outIndex++] = ((buffer ushr (bitsLeft - 8)) and 0xFF).toByte()
                }
                bitsLeft -= 8
            }
        }
        return out
    }
}
