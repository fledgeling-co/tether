package app.fledgeling.tether.ui

import app.fledgeling.tether.TetherRoute
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.assertThrows
import org.junit.Test

public class PairingFieldsTest {
    @Test public fun pairingCodeMatchesSharedRustAsciiFormattingAndAliases() {
        assertTrue(validPairingCode("ab-cd 2345"))
        assertTrue(validPairingCode("OIlo2345"))
        assertEquals("01102345", normalizedPairingCode("OIlo2345"))
        assertFalse(validPairingCode("ABCU2345"))
        assertFalse(validPairingCode("ABCß2345"))
        assertFalse(validPairingCode("ABCD\t2345"))
        assertFalse(validPairingCode("ABCD234"))
        assertFalse(validPairingCode("ABCD23456"))
        assertEquals("ABCD2345", normalizedPairingCode("ab cd 2345"))
    }

    @Test public fun privateRouteRequiresNonblankAddressAndBoundedPort() {
        assertEquals(TetherRoute.PrivateNetwork("host.local", 9000), pairingRoute(false, " host.local ", "9000", "", ""))
        for (value in listOf("0", "65536", "invalid")) assertThrows(IllegalArgumentException::class.java) {
            pairingRoute(false, "host.local", value, "", "")
        }
        assertThrows(IllegalArgumentException::class.java) { pairingRoute(false, " ", "9000", "", "") }
    }

    @Test public fun cloudChoiceRequiresExplicitSecureRelayAndHostId() {
        assertThrows(IllegalArgumentException::class.java) { pairingRoute(true, "", "", "http://example.com", "host") }
        assertThrows(IllegalArgumentException::class.java) { pairingRoute(true, "", "", "wss://example.com", "") }
    }
}
