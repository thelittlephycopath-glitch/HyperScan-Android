package com.hyperscan.android

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test

class SecretScannerTest {
    @Test fun detectsCommonCredentialPatternsWithoutReturningFullSecret() {
        val result = SecretScanner.scan("token = ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890")
        assertEquals(1, result.size)
        assertEquals("GitHub token", result.first().kind)
        assertFalse(result.first().masked.contains("ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"))
        assertEquals(64, result.first().fingerprint.length)
    }

    @Test fun doesNotFlagOrdinaryText() {
        assertEquals(0, SecretScanner.scan("hello world\nthis is documentation").size)
    }
}