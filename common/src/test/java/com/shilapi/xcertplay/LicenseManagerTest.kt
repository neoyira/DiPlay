package com.shilapi.xcertplay

import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [29])
class LicenseManagerTest {
    private val context get() = RuntimeEnvironment.getApplication()

    @Before
    fun setUp() {
        LicenseManager.forceEnforcementInTests = true
        LicenseManager.clearLicense(context)
    }

    @After
    fun tearDown() {
        LicenseManager.forceEnforcementInTests = false
        LicenseManager.clearLicense(context)
    }

    @Test
    fun deviceIdIsDeterministicAnd12CharsWithHyphens() {
        val id1 = LicenseManager.deviceId(context)
        val id2 = LicenseManager.deviceId(context)
        assertEquals(id1, id2)
        assertEquals(14, id1.length) // XXXX-XXXX-XXXX
        assertEquals(12, LicenseManager.normalizeCode(id1).length)
    }

    @Test
    fun mewitActivateHttp200CachesAndUnlocksDevice() {
        val devId = LicenseManager.deviceId(context)
        assertFalse(LicenseManager.isLicensed(context))

        val response200 = """
            {
              "ok": true,
              "product": "diplay",
              "expiry_date": "2028-11-06",
              "payload_base64": "eyJ2IjoxLCJwcm9kdWN0IjoiZGlwbGF5In0=",
              "signature_base64": "8fK3chuKyEd25519=="
            }
        """.trimIndent()

        val result = LicenseManager.handleActivateResponse(
            context = context,
            licenseKey = "MEWIT-ABCD-1234-EFGH",
            httpCode = 200,
            body = response200,
            devId = devId,
        )
        assertTrue(result.success)
        assertTrue(result.licensed)
        assertEquals(LicenseManager.Status.VALID_TIMED, result.state.status)
        assertEquals("2028-11-06", result.state.expiryDateText)
        assertTrue(LicenseManager.isLicensed(context))
    }

    @Test
    fun mewitActivateErrorCodesHandledCorrectly() {
        val devId = LicenseManager.deviceId(context)

        val r404 = LicenseManager.handleActivateResponse(
            context, "MEWIT-NOT-FOUND", 404, """{"error":"Mã bản quyền không tồn tại"}""", devId
        )
        assertFalse(r404.licensed)
        assertEquals(404, r404.httpCode)

        val r409 = LicenseManager.handleActivateResponse(
            context, "MEWIT-USED-KEY", 409, """{"error":"Key đang dùng trên máy khác"}""", devId
        )
        assertFalse(r409.licensed)
        assertEquals(409, r409.httpCode)

        val r403 = LicenseManager.handleActivateResponse(
            context, "MEWIT-REVOKED-KEY", 403, """{"error":"Key đã bị thu hồi"}""", devId
        )
        assertFalse(r403.licensed)
        assertEquals(403, r403.httpCode)
    }

    @Test
    fun mewitGetLicenseChecksValidDeviceMatchAndRevocation() {
        val devId = LicenseManager.deviceId(context)
        val statusValidJson = """
            {
              "username": "khach_vip_01",
              "license_key": "MEWIT-ABCD-1234-EFGH",
              "expiry_date": "2028-11-06",
              "status": "active",
              "product": "diplay",
              "valid": true,
              "is_expired": false,
              "is_revoked": false,
              "is_activated": true,
              "device_match": true,
              "device_label": "BYD DiLink 4.0"
            }
        """.trimIndent()

        val okRes = LicenseManager.handleStatusResponse(
            context, "MEWIT-ABCD-1234-EFGH", 200, statusValidJson, devId
        )
        assertTrue(okRes.success)
        assertTrue(okRes.licensed)
        assertEquals("khach_vip_01", okRes.state.username)
        assertTrue(LicenseManager.isLicensed(context))

        // Device mismatch locks the app
        val mismatchJson = """
            {
              "license_key": "MEWIT-ABCD-1234-EFGH",
              "product": "diplay",
              "valid": true,
              "device_match": false
            }
        """.trimIndent()
        val mismatchRes = LicenseManager.handleStatusResponse(
            context, "MEWIT-ABCD-1234-EFGH", 200, mismatchJson, devId
        )
        assertTrue(mismatchRes.success)
        assertFalse(mismatchRes.licensed)
        assertFalse(LicenseManager.isLicensed(context))

        // Revoked locks the app with REVOKED status
        val revokedJson = """
            {
              "license_key": "MEWIT-ABCD-1234-EFGH",
              "product": "diplay",
              "valid": false,
              "is_revoked": true,
              "device_match": true
            }
        """.trimIndent()
        val revokedRes = LicenseManager.handleStatusResponse(
            context, "MEWIT-ABCD-1234-EFGH", 200, revokedJson, devId
        )
        assertTrue(revokedRes.success)
        assertFalse(revokedRes.licensed)
        assertEquals(LicenseManager.Status.REVOKED, revokedRes.state.status)
    }

    @Test
    fun offlineFallbackKeyAndAntiRollbackWork() {
        val devId = LicenseManager.deviceId(context)
        val key = LicenseManager.generateLicenseKeyForDate(devId, "2026-12-31")
        val beforeExpiryMs = LicenseManager.EPOCH_2025_01_01_MS + 365L * 86_400_000L
        val afterExpiryMs = LicenseManager.EPOCH_2025_01_01_MS + 800L * 86_400_000L

        assertNull(LicenseManager.verifyKeyForDevice(key, "AAAA-BBBB-CCCC"))
        assertNotNull(LicenseManager.verifyKeyForDevice(key, devId))

        val activeState = LicenseManager.activateOffline(context, key, nowMs = beforeExpiryMs)
        assertEquals(LicenseManager.Status.VALID_TIMED, activeState.status)

        val expiredState = LicenseManager.state(context, nowMs = afterExpiryMs)
        assertEquals(LicenseManager.Status.EXPIRED, expiredState.status)

        // Rolling clock back must remain expired
        val rolledBackState = LicenseManager.state(context, nowMs = beforeExpiryMs)
        assertEquals(LicenseManager.Status.EXPIRED, rolledBackState.status)
    }
}
