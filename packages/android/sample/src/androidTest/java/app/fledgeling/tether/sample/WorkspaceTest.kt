package app.fledgeling.tether.sample

import android.content.Intent
import android.graphics.Bitmap
import android.os.SystemClock
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.assertIsEnabled
import androidx.compose.ui.test.assertHeightIsAtLeast
import androidx.compose.ui.test.assertTouchHeightIsEqualTo
import androidx.compose.ui.test.assertWidthIsAtLeast
import androidx.compose.ui.unit.dp
import androidx.compose.ui.test.junit4.createEmptyComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.test.performTextInput
import androidx.compose.ui.test.performImeAction
import androidx.compose.ui.test.assertTextContains
import androidx.compose.ui.test.performTextReplacement
import androidx.test.core.app.ActivityScenario
import androidx.test.core.app.ApplicationProvider
import androidx.test.platform.app.InstrumentationRegistry
import java.io.File
import org.json.JSONObject
import org.junit.Rule
import org.junit.Test

public class WorkspaceTest {
    @get:Rule public val compose = createEmptyComposeRule()

    @Test public fun compactSelectionAndRemovalConsequences() {
        val intent = Intent(ApplicationProvider.getApplicationContext(), MainActivity::class.java)
            .putExtra("tether.designFixtures", true)
        ActivityScenario.launch<MainActivity>(intent).use {
            compose.onNodeWithText("studio-1.local:9000").assertIsDisplayed()
            capture("android-hosts-light")
            compose.onNodeWithText("studio-2.local:9000").performClick()
            compose.onNodeWithText("Access removed").assertIsDisplayed()
            capture("android-revoked-light")
            compose.onNodeWithTag("tether.forget").performScrollTo().performClick()
            compose.onNodeWithText("Forget this host locally?").assertIsDisplayed()
            capture("android-forget-confirmation")
            compose.onNodeWithText("Cancel").performClick()
            compose.onNodeWithTag("tether.forget").assertExists()
        }
    }

    @Test public fun manualPairingFailureKeepsEditableFields() {
        val intent = Intent(ApplicationProvider.getApplicationContext(), MainActivity::class.java)
            .putExtra("tether.designFixtures", true)
        ActivityScenario.launch<MainActivity>(intent).use {
            compose.onNodeWithTag("tether.pair").assertTouchHeightIsEqualTo(48.dp).assertWidthIsAtLeast(48.dp).performClick()
            compose.onNodeWithTag("tether.pair.submit").assertIsNotEnabled()
            compose.onNodeWithText("Scan invitation").assertDoesNotExist()
            compose.onNodeWithTag("tether.pair.address").performTextInput("unreachable.invalid")
            compose.onNodeWithTag("tether.pair.code").performTextInput("ABCD2345")
            compose.onNodeWithTag("tether.pair.code").performImeAction()
            compose.onNodeWithTag("tether.pair.submit").performScrollTo().assertHeightIsAtLeast(48.dp).performClick()
            compose.onNodeWithTag("tether.pair.error").performScrollTo().assertIsDisplayed()
            capture("android-pairing-error")
            compose.onNodeWithTag("tether.pair.address").performScrollTo().assertTextContains("unreachable.invalid")
            compose.onNodeWithTag("tether.pair.address").performTextReplacement("host.local")
            compose.onNodeWithTag("tether.pair.address").assertTextContains("host.local")
            compose.onNodeWithTag("tether.pair.invitation").performScrollTo().performTextInput("tether://pair?invalid")
            compose.onNodeWithText("Use invitation").performScrollTo().performClick()
            compose.onNodeWithTag("tether.pair.submit").assertIsNotEnabled()
            compose.onNodeWithText("Cancel").performClick()
            compose.onNodeWithTag("tether.pair").performClick()
            compose.onNodeWithTag("tether.pair.submit").assertIsNotEnabled()
            compose.onNodeWithTag("tether.pair.cloud").performScrollTo().performClick()
            compose.onNodeWithTag("tether.pair.relay").assertIsDisplayed()
            compose.onNodeWithTag("tether.pair.hostId").assertIsDisplayed()
            capture("android-pairing-cloud")
        }
    }

    @Test public fun expandedLandscapeUsesBothPanesInDarkTheme() {
        val intent = Intent(ApplicationProvider.getApplicationContext(), MainActivity::class.java)
            .putExtra("tether.designFixtures", true).putExtra("tether.dark", true).putExtra("tether.landscape", true)
        ActivityScenario.launch<MainActivity>(intent).use {
            compose.onNodeWithTag("tether.hosts").assertIsDisplayed()
            compose.onNodeWithTag("tether.host.status").assertIsDisplayed()
            capture("android-wide-dark")
            compose.onNodeWithText("studio-3.local:9000").performScrollTo().assertIsDisplayed()
            compose.onNodeWithTag("tether.forget").performScrollTo().assertIsDisplayed()
            compose.onNodeWithText("studio-3.local:9000").assertIsDisplayed()
        }
    }

    @Test public fun attentionStatesExposeTheAppropriateRecoveryActions() {
        val intent = Intent(ApplicationProvider.getApplicationContext(), MainActivity::class.java)
            .putExtra("tether.designFixtures", true).putExtra("tether.allStates", true)
        ActivityScenario.launch<MainActivity>(intent).use {
            compose.onNodeWithText("studio-3.local:9000").performScrollTo().performClick()
            compose.onNodeWithText("Host identity changed").assertIsDisplayed()
            compose.onNodeWithTag("tether.reconnect").assertDoesNotExist()
            compose.onNodeWithTag("tether.leave").performScrollTo().assertIsNotEnabled()
            compose.onNodeWithTag("tether.hosts.back").performClick()
            compose.onNodeWithText("studio-4.local:9000").performScrollTo().performClick()
            compose.onNodeWithTag("tether.cancel.connection").performScrollTo().assertIsEnabled()
            compose.onNodeWithTag("tether.hosts.back").performClick()
            compose.onNodeWithText("studio-5.local:9000").performScrollTo().performClick()
            compose.onNodeWithTag("tether.recover").performScrollTo().assertIsEnabled()
            compose.onNodeWithTag("tether.forget").assertDoesNotExist()
            compose.onNodeWithTag("tether.hosts.back").performClick()
            compose.onNodeWithText("studio-6.local:9000").performScrollTo().performClick()
            compose.onNodeWithText("application-api").performScrollTo().assertIsDisplayed()
            compose.onNodeWithText("media").performScrollTo().assertIsDisplayed()
            compose.onNodeWithText("Disconnect").performScrollTo().assertIsEnabled()
            compose.onNodeWithTag("tether.hosts.back").performClick()
            compose.onNodeWithText("studio-7.local:9000").performScrollTo().performClick()
            compose.onNodeWithText("Host at capacity").assertIsDisplayed()
            compose.onNodeWithTag("tether.reconnect").performScrollTo().assertIsEnabled()
            compose.onNodeWithTag("tether.hosts.back").performClick()
            compose.onNodeWithText("studio-8.local:9000").performScrollTo().performClick()
            compose.onNodeWithText("Connection needs attention").assertIsDisplayed()
            compose.onNodeWithTag("tether.reconnect").performScrollTo().assertIsEnabled()
        }
    }

    private fun capture(name: String) {
        compose.waitForIdle()
        val instrument = InstrumentationRegistry.getInstrumentation()
        instrument.waitForIdleSync()
        // Compose idleness does not include the platform Dialog window's compositor fade.
        SystemClock.sleep(500)
        val screenshot = requireNotNull(instrument.uiAutomation.takeScreenshot())
        val folder = File(instrument.targetContext.getExternalFilesDir(null), "tether-ui-evidence").apply { mkdirs() }
        File(folder, "$name.png").outputStream().use { check(screenshot.compress(Bitmap.CompressFormat.PNG, 100, it)) }
        File(folder, "$name.json").writeText(JSONObject()
            .put("schema", "tether.android-ui-capture/1")
            .put("screen", name).put("fixture", true).put("compositorSettlingMillis", 500).put("source", "Android UiAutomation.takeScreenshot")
            .put("package", instrument.targetContext.packageName).put("activity", MainActivity::class.java.name)
            .put("width", screenshot.width).put("height", screenshot.height)
            .put("density", instrument.targetContext.resources.displayMetrics.density)
            .put("fontScale", instrument.targetContext.resources.configuration.fontScale)
            .put("api", android.os.Build.VERSION.SDK_INT).put("capturedAtEpochMillis", System.currentTimeMillis())
            .toString(2))
        screenshot.recycle()
    }
}
