// SPDX-License-Identifier: AGPL-3.0-only
package com.shilapi.xcertplay

import android.content.Context
import android.os.Build
import android.provider.Settings
import org.json.JSONObject
import java.io.BufferedReader
import java.io.InputStreamReader
import java.net.HttpURLConnection
import java.net.URL
import java.net.URLEncoder
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.TimeZone
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import kotlin.math.ceil

/**
 * Hybrid Offline + Online License Manager for DiPlay.
 *
 * - Generates a deterministic 12-character Device ID (`XXXX-XXXX-XXXX`) per head unit.
 * - Verifies 16-character Offline License Keys (`XXXX-XXXX-XXXX-XXXX`) with embedded expiration
 *   date (or Lifetime `0xFFFF`) and HMAC-SHA256 cryptographic authentication.
 * - Supports Online License activation/revocation against a remote JSON/REST endpoint.
 * - Protects time-limited licenses against system clock rollback.
 */
object LicenseManager {
    private const val PREFS = "diplay_license"
    private const val KEY_LICENSE_CODE = "license_code"
    private const val KEY_ONLINE_EXPIRY_DAYS = "online_expiry_days"
    private const val KEY_ONLINE_VERIFIED_DEVICE = "online_verified_device"
    private const val KEY_REVOKED = "license_revoked"
    private const val KEY_REVOKED_REASON = "license_revoked_reason"
    private const val KEY_LAST_SEEN_EPOCH_MS = "last_seen_epoch_ms"
    private const val KEY_ONLINE_SERVER_URL = "online_server_url"
    private const val KEY_CACHED_DEVICE_ID = "cached_device_id"

    /** Base epoch for expiration day calculation: 2025-01-01 00:00:00 UTC. */
    const val EPOCH_2025_01_01_MS = 1735689600000L
    const val LIFETIME_EXPIRY_DAYS = 0xFFFF
    private const val DAY_MS = 86_400_000L
    private const val ALPHABET = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"

    /**
     * Default remote JSON/API endpoint for 1-click online activation & revocation.
     * Can also be overridden in UI settings.
     */
    const val DEFAULT_ONLINE_LICENSE_URL =
        "https://raw.githubusercontent.com/neoyira/DiPlay/main/licenses.json"

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
        val daysRemaining: Int?,
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

    data class OnlineCheckResult(
        val success: Boolean,
        val licensed: Boolean,
        val message: String,
        val state: LicenseState,
    )

    // Obfuscated signing secret so simple string scans on the APK do not reveal the HMAC key.
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

    /**
     * Generates a 16-character offline license key (`XXXX-XXXX-XXXX-XXXX`).
     *
     * @param targetDeviceId 12-character device ID, or `"*"` / `""` for a universal key.
     * @param expiryDays [LIFETIME_EXPIRY_DAYS] (`65535`) for lifetime, or days since 2025-01-01 UTC.
     */
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

    /**
     * Generates a license key that expires at the end of the given `yyyy-MM-dd` UTC date.
     */
    fun generateLicenseKeyForDate(targetDeviceId: String, utcDateYmd: String): String {
        val days = dateToExpiryDays(utcDateYmd)
        return generateLicenseKey(targetDeviceId, days)
    }

    fun dateToExpiryDays(utcDateYmd: String): Int {
        val sdf = SimpleDateFormat("yyyy-MM-dd", Locale.US).apply {
            timeZone = TimeZone.getTimeZone("UTC")
            isLenient = false
        }
        val parsed = sdf.parse(utcDateYmd.trim()) ?: error("Invalid date: $utcDateYmd")
        val diffDays = ((parsed.time - EPOCH_2025_01_01_MS) / DAY_MS).toInt()
        require(diffDays in 1 until LIFETIME_EXPIRY_DAYS) { "Expiry date must be after 2025-01-01" }
        return diffDays
    }

    fun expiryDaysToEpochMs(expiryDays: Int): Long? {
        if (expiryDays == LIFETIME_EXPIRY_DAYS) return null
        // Valid through the end of the expiration day (23:59:59.999 UTC).
        return EPOCH_2025_01_01_MS + (expiryDays.toLong() + 1L) * DAY_MS - 1L
    }

    /**
     * Verifies whether [licenseKey] is cryptographically valid for [deviceId].
     */
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
        val p = prefs(context)
        if (p.getBoolean(KEY_REVOKED, false)) {
            return LicenseState(
                status = Status.REVOKED,
                deviceId = devId,
                licenseKey = p.getString(KEY_LICENSE_CODE, null),
                expiresAtEpochMs = null,
                daysRemaining = 0,
                revokedReason = p.getString(KEY_REVOKED_REASON, null),
            )
        }
        val effectiveNow = effectiveNowMs(context, nowMs)
        val storedKey = p.getString(KEY_LICENSE_CODE, null)
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
                        daysRemaining = daysLeft,
                    )
                } else {
                    LicenseState(
                        status = Status.EXPIRED,
                        deviceId = devId,
                        licenseKey = parsed.formattedKey,
                        expiresAtEpochMs = expiresAt,
                        daysRemaining = 0,
                    )
                }
            }
        }

        // Check online activation record if present
        val onlineVerifiedDevice = p.getString(KEY_ONLINE_VERIFIED_DEVICE, null)
        val onlineExpiryDays = p.getInt(KEY_ONLINE_EXPIRY_DAYS, 0)
        if (onlineVerifiedDevice == normalizeCode(devId) && onlineExpiryDays > 0) {
            val expiresAt = expiryDaysToEpochMs(onlineExpiryDays)
            if (expiresAt == null) {
                return LicenseState(
                    status = Status.VALID_LIFETIME,
                    deviceId = devId,
                    licenseKey = "ONLINE",
                    expiresAtEpochMs = null,
                    daysRemaining = null,
                    isOnlineActivated = true,
                )
            }
            val remainingMs = expiresAt - effectiveNow
            return if (remainingMs >= 0L) {
                val daysLeft = ceil(remainingMs.toDouble() / DAY_MS.toDouble()).toInt().coerceAtLeast(1)
                LicenseState(
                    status = Status.VALID_TIMED,
                    deviceId = devId,
                    licenseKey = "ONLINE",
                    expiresAtEpochMs = expiresAt,
                    daysRemaining = daysLeft,
                    isOnlineActivated = true,
                )
            } else {
                LicenseState(
                    status = Status.EXPIRED,
                    deviceId = devId,
                    licenseKey = "ONLINE",
                    expiresAtEpochMs = expiresAt,
                    daysRemaining = 0,
                    isOnlineActivated = true,
                )
            }
        }

        return LicenseState(
            status = Status.UNLICENSED,
            deviceId = devId,
            licenseKey = null,
            expiresAtEpochMs = null,
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
     * Attempts to activate with an offline license key.
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

    fun clearLicense(context: Context) {
        prefs(context).edit()
            .remove(KEY_LICENSE_CODE)
            .remove(KEY_ONLINE_EXPIRY_DAYS)
            .remove(KEY_ONLINE_VERIFIED_DEVICE)
            .remove(KEY_REVOKED)
            .remove(KEY_REVOKED_REASON)
            .apply()
    }

    fun onlineServerUrl(context: Context): String =
        prefs(context).getString(KEY_ONLINE_SERVER_URL, null)
            ?.takeIf { it.isNotBlank() }
            ?: DEFAULT_ONLINE_LICENSE_URL

    fun saveOnlineServerUrl(context: Context, url: String) {
        val trimmed = url.trim()
        prefs(context).edit().apply {
            if (trimmed.isEmpty() || trimmed == DEFAULT_ONLINE_LICENSE_URL) remove(KEY_ONLINE_SERVER_URL)
            else putString(KEY_ONLINE_SERVER_URL, trimmed)
        }.apply()
    }

    /**
     * Verifies or activates the device against an online JSON/REST endpoint.
     */
    fun verifyOnline(
        context: Context,
        customUrl: String? = null,
        timeoutMs: Int = 8_000,
    ): OnlineCheckResult {
        val devId = deviceId(context)
        val cleanDev = normalizeCode(devId)
        val baseUrl = (customUrl ?: onlineServerUrl(context)).trim()
        if (baseUrl.isEmpty()) {
            return OnlineCheckResult(
                success = false,
                licensed = isLicensed(context),
                message = "Chưa cấu hình URL máy chủ kích hoạt / No license server URL configured.",
                state = state(context),
            )
        }
        return try {
            val separator = if ('?' in baseUrl) '&' else '?'
            val requestUrl = "$baseUrl${separator}device_id=${URLEncoder.encode(devId, "UTF-8")}"
            val connection = (URL(requestUrl).openConnection() as HttpURLConnection).apply {
                connectTimeout = timeoutMs
                readTimeout = timeoutMs
                requestMethod = "GET"
                useCaches = false
                setRequestProperty("Accept", "application/json")
                setRequestProperty("User-Agent", "DiPlay-LicenseClient/1.0")
            }
            val code = connection.responseCode
            if (code !in 200..299) {
                return OnlineCheckResult(
                    success = false,
                    licensed = isLicensed(context),
                    message = "Máy chủ trả về mã HTTP $code / Server returned HTTP $code",
                    state = state(context),
                )
            }
            val body = BufferedReader(InputStreamReader(connection.inputStream, StandardCharsets.UTF_8))
                .use(BufferedReader::readText)
            applyOnlineResponse(context, body, devId, cleanDev)
        } catch (error: Throwable) {
            OnlineCheckResult(
                success = false,
                licensed = isLicensed(context),
                message = "Không thể kết nối máy chủ: ${error.localizedMessage ?: error.javaClass.simpleName}",
                state = state(context),
            )
        }
    }

    internal fun applyOnlineResponse(
        context: Context,
        jsonText: String,
        devId: String = deviceId(context),
        cleanDev: String = normalizeCode(devId),
    ): OnlineCheckResult {
        val root = JSONObject(jsonText)
        val record: JSONObject? = when {
            root.has("devices") -> {
                val devices = root.optJSONObject("devices")
                devices?.optJSONObject(devId)
                    ?: devices?.optJSONObject(cleanDev)
                    ?: devices?.keys()?.asSequence()?.firstOrNull { key ->
                        normalizeCode(key) == cleanDev
                    }?.let(devices::optJSONObject)
            }
            root.has(devId) -> root.optJSONObject(devId)
            root.has(cleanDev) -> root.optJSONObject(cleanDev)
            root.has("status") || root.has("valid") || root.has("key") -> root
            else -> null
        }

        if (record == null) {
            return OnlineCheckResult(
                success = true,
                licensed = isLicensed(context),
                message = "Thiết bị $devId chưa có trong danh sách kích hoạt Online.",
                state = state(context),
            )
        }

        val statusStr = record.optString("status", "").lowercase(Locale.US)
        val revoked = record.optBoolean("revoked", false) || statusStr == "revoked" || statusStr == "blocked"
        if (revoked) {
            val reason = record.optString("reason", "Bản quyền đã bị thu hồi từ máy chủ.")
            prefs(context).edit()
                .putBoolean(KEY_REVOKED, true)
                .putString(KEY_REVOKED_REASON, reason)
                .apply()
            val updated = state(context)
            return OnlineCheckResult(
                success = true,
                licensed = false,
                message = reason,
                state = updated,
            )
        }

        val explicitKey = record.optString("key", "").trim()
        if (explicitKey.isNotEmpty()) {
            val activated = activateOffline(context, explicitKey)
            if (activated.isValid) {
                return OnlineCheckResult(
                    success = true,
                    licensed = true,
                    message = "Đã kích hoạt bản quyền Online thành công!",
                    state = activated,
                )
            }
        }

        val validFlag = record.optBoolean("valid", statusStr == "active" || statusStr == "valid" || statusStr == "licensed")
        if (!validFlag) {
            return OnlineCheckResult(
                success = true,
                licensed = isLicensed(context),
                message = "Thiết bị chưa được cấp phép trên máy chủ.",
                state = state(context),
            )
        }

        val expiresRaw = record.optString("expires", "lifetime").trim().lowercase(Locale.US)
        val expiryDays = when {
            expiresRaw.isEmpty() || expiresRaw == "lifetime" || expiresRaw == "permanent" || expiresRaw == "never" ->
                LIFETIME_EXPIRY_DAYS
            else -> runCatching { dateToExpiryDays(expiresRaw) }.getOrDefault(LIFETIME_EXPIRY_DAYS)
        }
        // Generate and persist a signed key for this device so offline usage continues seamlessly.
        val generatedKey = generateLicenseKey(devId, expiryDays)
        prefs(context).edit()
            .putString(KEY_LICENSE_CODE, generatedKey)
            .putString(KEY_ONLINE_VERIFIED_DEVICE, cleanDev)
            .putInt(KEY_ONLINE_EXPIRY_DAYS, expiryDays)
            .remove(KEY_REVOKED)
            .remove(KEY_REVOKED_REASON)
            .apply()
        val updated = state(context)
        return OnlineCheckResult(
            success = true,
            licensed = updated.isValid,
            message = if (updated.isValid) "Đã kích hoạt bản quyền Online thành công!" else "Bản quyền trên máy chủ đã hết hạn.",
            state = updated,
        )
    }

    fun formatExpiryDate(epochMs: Long?): String {
        if (epochMs == null) return "Vĩnh viễn / Lifetime"
        val sdf = SimpleDateFormat("dd/MM/yyyy", Locale.US).apply {
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
