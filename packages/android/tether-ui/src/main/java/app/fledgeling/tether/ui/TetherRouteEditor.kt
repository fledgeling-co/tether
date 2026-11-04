package app.fledgeling.tether.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import app.fledgeling.tether.TetherRoute
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.launch

/** Saving checks the existing pinned host before the embedding store commits a new route. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
public fun TetherRouteEditor(
    route: TetherRoute,
    onSave: suspend (TetherRoute) -> Unit,
    onClose: () -> Unit,
    modifier: Modifier = Modifier,
) {
    var cloud by remember(route) { mutableStateOf(route is TetherRoute.Cloud) }
    var address by remember(route) { mutableStateOf((route as? TetherRoute.PrivateNetwork)?.host ?: "") }
    var port by remember(route) { mutableStateOf((route as? TetherRoute.PrivateNetwork)?.port?.toString() ?: "9000") }
    var relay by remember(route) { mutableStateOf((route as? TetherRoute.Cloud)?.relayUrl ?: "") }
    var hostId by remember(route) { mutableStateOf((route as? TetherRoute.Cloud)?.hostId ?: "") }
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    val scope = rememberCoroutineScope()
    Scaffold(modifier = modifier, topBar = {
        TopAppBar(title = { Text("Change connection") }, navigationIcon = {
            TextButton(onClick = onClose) { Text("Cancel") }
        })
    }) { insets ->
        Column(Modifier.fillMaxSize().padding(insets).imePadding().verticalScroll(rememberScrollState()).padding(24.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp)) {
            Text("Keep the same host identity", style = MaterialTheme.typography.headlineSmall)
            Text("The new endpoint must authenticate as the host you already paired. Failure keeps the saved route and open streams.",
                color = MaterialTheme.colorScheme.onSurfaceVariant)
            FilterChip(selected = !cloud, enabled = !busy, onClick = { cloud = false }, label = { Text("Private network or VPN") })
            FilterChip(selected = cloud, enabled = !busy, onClick = { cloud = true }, label = { Text("Cloud relay") })
            if (cloud) {
                OutlinedTextField(relay, { relay = it }, label = { Text("Relay URL") }, singleLine = true, enabled = !busy,
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri), modifier = Modifier.fillMaxWidth())
                OutlinedTextField(hostId, { hostId = it }, label = { Text("Cloud host ID") }, singleLine = true, enabled = !busy, modifier = Modifier.fillMaxWidth())
            } else {
                OutlinedTextField(address, { address = it }, label = { Text("Host address") }, singleLine = true, enabled = !busy,
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri), modifier = Modifier.fillMaxWidth())
                OutlinedTextField(port, { port = it }, label = { Text("Port") }, singleLine = true, enabled = !busy,
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number), modifier = Modifier.fillMaxWidth())
            }
            error?.let { Text(it, color = MaterialTheme.colorScheme.error, modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite }) }
            Button(onClick = {
                busy = true; error = null
                scope.launch {
                    try { onSave(pairingRoute(cloud, address, port, relay, hostId)); onClose() }
                    catch (_: CancellationException) { throw CancellationException() }
                    catch (_: Exception) { error = "The new endpoint could not authenticate as the saved host. Its existing route and trust are retained. Check the details and retry." }
                    finally { busy = false }
                }
            }, enabled = !busy, modifier = Modifier.fillMaxWidth().testTag("tether.route.save")) { Text(if (busy) "Checking host…" else "Check and save") }
        }
    }
}
