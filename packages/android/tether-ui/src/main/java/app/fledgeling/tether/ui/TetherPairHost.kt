package app.fledgeling.tether.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.platform.LocalSoftwareKeyboardController
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import app.fledgeling.tether.TetherPairingInvitation
import app.fledgeling.tether.TetherRoute
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch

/** Optional scanning is owned by the embedding app; this module requests no camera permission. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
public fun TetherPairHost(
    appId: String,
    onPair: suspend (TetherRoute, String) -> Unit,
    onClose: () -> Unit,
    modifier: Modifier = Modifier,
    onScanInvitation: (suspend () -> String?)? = null,
) {
    var cloud by rememberSaveable { mutableStateOf(false) }
    var address by rememberSaveable { mutableStateOf("") }
    var port by rememberSaveable { mutableStateOf("9000") }
    var relay by rememberSaveable { mutableStateOf("") }
    var hostId by rememberSaveable { mutableStateOf("") }
    // Pairing secrets are deliberately excluded from saved instance state.
    var code by remember { mutableStateOf("") }
    var invitation by remember { mutableStateOf("") }
    var error by remember { mutableStateOf<String?>(null) }
    var busy by remember { mutableStateOf(false) }
    var operation by remember { mutableStateOf<Job?>(null) }
    val scope = rememberCoroutineScope()
    val keyboard = LocalSoftwareKeyboardController.current
    DisposableEffect(Unit) { onDispose { operation?.cancel(); code = ""; invitation = "" } }

    fun importInvitation(value: String) {
        try {
            val decoded = TetherPairingInvitation.decode(value, appId)
            when (val route = decoded.route) {
                is TetherRoute.PrivateNetwork -> { cloud = false; address = route.host; port = route.port.toString() }
                is TetherRoute.Cloud -> { cloud = true; relay = route.relayUrl; hostId = route.hostId }
            }
            code = decoded.code; invitation = ""; error = null
        } catch (_: Exception) {
            code = ""; invitation = ""
            error = "This invitation cannot be used by this app. Check that it is current and was created for the same app."
        }
    }

    Scaffold(
        modifier = modifier,
        topBar = {
            TopAppBar(title = { Text("Pair host") }, navigationIcon = {
                TextButton(onClick = {
                    operation?.cancel(); code = ""; invitation = ""; onClose()
                }) { Text("Cancel") }
            })
        },
    ) { insets ->
        Column(
            Modifier.fillMaxSize().padding(insets).imePadding().verticalScroll(rememberScrollState())
                .padding(horizontal = 24.dp, vertical = 16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            Text("Connect to your Mac or PC", style = MaterialTheme.typography.headlineSmall)
            Text("Open the host’s pairing window, then enter its connection details and current code.",
                color = MaterialTheme.colorScheme.onSurfaceVariant)
            Column {
                Text("Connection", style = MaterialTheme.typography.labelLarge)
                FilterChip(selected = !cloud, enabled = !busy, onClick = { cloud = false },
                    label = { Text("Private network or VPN") }, modifier = Modifier.testTag("tether.pair.private"))
                FilterChip(selected = cloud, enabled = !busy, onClick = { cloud = true },
                    label = { Text("Cloud relay") }, modifier = Modifier.testTag("tether.pair.cloud"))
            }
            if (cloud) {
                OutlinedTextField(relay, { relay = it }, label = { Text("Relay URL") },
                    supportingText = { Text("Use the wss:// address shown by the host.") },
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri),
                    singleLine = true, enabled = !busy, modifier = Modifier.fillMaxWidth().testTag("tether.pair.relay"))
                OutlinedTextField(hostId, { hostId = it }, label = { Text("Cloud host ID") },
                    singleLine = true, enabled = !busy, modifier = Modifier.fillMaxWidth().testTag("tether.pair.hostId"))
                Text("The relay forwards encrypted traffic. Your host serves the application data.",
                    style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            } else {
                OutlinedTextField(address, { address = it }, label = { Text("Host address") },
                    supportingText = { Text("For example, host.local or a reachable VPN address.") },
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri),
                    singleLine = true, enabled = !busy, modifier = Modifier.fillMaxWidth().testTag("tether.pair.address"))
                OutlinedTextField(port, { port = it }, label = { Text("Port") },
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                    singleLine = true, enabled = !busy, modifier = Modifier.fillMaxWidth().testTag("tether.pair.port"))
                Text("Both devices must be able to reach the same private network. Selecting this route never enables cloud access.",
                    style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            val invalidCode = normalizedPairingCode(code).length >= 8 && !validPairingCode(code)
            OutlinedTextField(code, { code = it.take(32) }, label = { Text("Pairing code") }, isError = invalidCode,
                supportingText = { Text(if (invalidCode) "Use the eight characters shown by the host. I, L, O and U are not used." else "Eight characters from the host’s current pairing window.") },
                visualTransformation = PasswordVisualTransformation(),
                keyboardOptions = KeyboardOptions(capitalization = KeyboardCapitalization.Characters, keyboardType = KeyboardType.Password, autoCorrectEnabled = false, imeAction = ImeAction.Done),
                keyboardActions = KeyboardActions(onDone = { keyboard?.hide() }),
                singleLine = true, enabled = !busy, modifier = Modifier.fillMaxWidth().testTag("tether.pair.code"))
            error?.let { Text(it, color = MaterialTheme.colorScheme.error,
                modifier = Modifier.testTag("tether.pair.error").semantics { liveRegion = LiveRegionMode.Polite }) }
            Button(
                enabled = !busy && validPairingCode(code),
                onClick = {
                    busy = true; error = null
                    operation = scope.launch {
                        try {
                            val route = pairingRoute(cloud, address, port, relay, hostId)
                            onPair(route, normalizedPairingCode(code)); code = ""; onClose()
                        } catch (_: CancellationException) {
                            code = ""
                        } catch (_: Exception) {
                            error = "Pairing did not complete. Check the connection details, current code and host’s pairing window, then try again."
                        } finally { busy = false }
                    }
                }, modifier = Modifier.fillMaxWidth().testTag("tether.pair.submit"),
                contentPadding = PaddingValues(16.dp),
            ) {
                if (busy) {
                    CircularProgressIndicator(Modifier.size(18.dp), strokeWidth = 2.dp)
                    Text("Pairing…", Modifier.padding(start = 12.dp))
                }
                else Text("Pair host")
            }
            HorizontalDivider()
            Text("Have a pairing invitation?", style = MaterialTheme.typography.titleMedium)
            OutlinedTextField(invitation, { invitation = it.take(8_192) }, label = { Text("Invitation link") },
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password, autoCorrectEnabled = false),
                visualTransformation = PasswordVisualTransformation(), singleLine = true, enabled = !busy,
                modifier = Modifier.fillMaxWidth().testTag("tether.pair.invitation"))
            TextButton(enabled = !busy && invitation.isNotBlank(), onClick = { importInvitation(invitation) }) { Text("Use invitation") }
            onScanInvitation?.let { scanner ->
                TextButton(enabled = !busy, onClick = {
                    busy = true; error = null
                    operation = scope.launch {
                        try { scanner()?.let { importInvitation(it) } }
                        catch (_: CancellationException) { }
                        catch (_: Exception) { error = "The invitation could not be scanned. Paste its link or enter the host’s details instead." }
                        finally { busy = false }
                    }
                }) { Text("Scan invitation") }
            }
            Text("An invitation contains a temporary pairing secret. Share it only with the device you intend to pair.",
                style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            Spacer(Modifier.height(8.dp))
        }
    }
}

// Match the shared Rust code entry format; Rust remains the protocol authority.
internal fun normalizedPairingCode(value: String): String = buildString {
    value.forEach { character ->
        if (character != ' ' && character != '-') {
            val upper = if (character in 'a'..'z') character.uppercaseChar() else character
            append(when (upper) { 'O' -> '0'; 'I', 'L' -> '1'; else -> upper })
        }
    }
}
internal fun validPairingCode(value: String): Boolean = value.length <= 32 && Regex("[0-9A-HJKMNP-TV-Z]{8}").matches(normalizedPairingCode(value))

internal fun pairingRoute(cloud: Boolean, address: String, port: String, relay: String, hostId: String): TetherRoute {
    if (cloud) {
        require(relay.trim().startsWith("wss://") && hostId.isNotBlank()) { "Use a secure relay and host ID." }
        return TetherRoute.Cloud(relay.trim(), hostId.trim())
    }
    val number = port.trim().toIntOrNull()
    require(address.isNotBlank() && number != null && number in 1..65535) { "Use a host address and valid port." }
    return TetherRoute.PrivateNetwork(address.trim(), number)
}
