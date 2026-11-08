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
    fun lifetimeDeviceKeyActivatesOnlyTargetDevice() {
        val devId = LicenseManager.deviceId(context)
        assertFalse(LicenseManager.isLicensed(context))

        val key = LicenseManager.generateLicenseKey(devId, LicenseManager.LIFETIME_EXPIRY_DAYS)
        assertEquals(19, key.length) // XXXX-XXXX-XXXX-XXXX

        // Must fail on a different device ID
        assertNull(LicenseManager.verifyKeyForDevice(key, "AAAA-BBBB-CCCC"))

        // Must succeed on the target device
        val parsed = LicenseManager.verifyKeyForDevice(key, devId)
        assertNotNull(parsed)
        assertTrue(parsed!!.isLifetime)
        assertFalse(parsed.isUniversal)

        val state = LicenseManager.activateOffline(context, key)
        assertEquals(LicenseManager.Status.VALID_LIFETIME, state.status)
        assertTrue(LicenseManager.isLicensed(context))
    }

    @Test
    fun universalKeyWorksOnAnyDevice() {
        val key = LicenseManager.generateLicenseKey("*", LicenseManager.LIFETIME_EXPIRY_DAYS)
        val parsed1 = LicenseManager.verifyKeyForDevice(key, "2345-6789-ABCD")
        val parsed2 = LicenseManager.verifyKeyForDevice(key, "WXYZ-9876-5432")
        assertNotNull(parsed1)
        assertNotNull(parsed2)
        assertTrue(parsed1!!.isUniversal)
    }

    @Test
    fun timedKeyExpiresAndResistsClockRollback() {
        val devId = LicenseManager.deviceId(context)
        val key = LicenseManager.generateLicenseKeyForDate(devId, "2026-12-31")
        val beforeExpiryMs = LicenseManager.EPOCH_2025_01_01_MS + 365L * 86_400_000L // 2026-01-01
        val afterExpiryMs = LicenseManager.EPOCH_2025_01_01_MS + 800L * 86_400_000L // 2027-03-12

        val activeState = LicenseManager.activateOffline(context, key, nowMs = beforeExpiryMs)
        assertEquals(LicenseManager.Status.VALID_TIMED, activeState.status)
        assertTrue(activeState.daysRemaining!! > 300)

        // Advance clock past expiration
        val expiredState = LicenseManager.state(context, nowMs = afterExpiryMs)
        assertEquals(LicenseManager.Status.EXPIRED, expiredState.status)
        assertFalse(expiredState.isValid)

        // Roll clock back to 2026-01-01 -> must still be expired due to anti-rollback protection
        val rolledBackState = LicenseManager.state(context, nowMs = beforeExpiryMs)
        assertEquals(LicenseManager.Status.EXPIRED, rolledBackState.status)
    }

    @Test
    fun onlineResponseActivatesAndRevokes() {
        val devId = LicenseManager.deviceId(context)
        val activeJson = """
            {
              "devices": {
                "$devId": {
                  "status": "active",
                  "expires": "2028-06-30",
                  "note": "BYD Seal test car"
                }
              }
            }
        """.trimIndent()
        val result = LicenseManager.applyOnlineResponse(context, activeJson)
        assertTrue(result.success)
        assertTrue(result.licensed)
        assertEquals(LicenseManager.Status.VALID_TIMED, result.state.status)

        val revokeJson = """
            {
              "devices": {
                "$devId": {
                  "status": "revoked",
                  "reason": "Hết hạn dùng thử"
                }
              }
            }
        """.trimIndent()
        val revoked = LicenseManager.applyOnlineResponse(context, revokeJson)
        assertTrue(revoked.success)
        assertFalse(revoked.licensed)
        assertEquals(LicenseManager.Status.REVOKED, revoked.state.status)
        assertEquals("Hết hạn dùng thử", revoked.state.revokedReason)
    }
}
