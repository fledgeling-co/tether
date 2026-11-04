package app.fledgeling.tether.ui

import android.util.Base64
import androidx.activity.compose.BackHandler
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.ListItem
import androidx.compose.material3.ListItemDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.VerticalDivider
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.stateDescription
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import app.fledgeling.tether.ConnectionState
import app.fledgeling.tether.HostService
import app.fledgeling.tether.ManagedHost
import app.fledgeling.tether.PeerRecord
import app.fledgeling.tether.TetherConnectionStore
import app.fledgeling.tether.TetherRoute
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Job
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.launch
import java.security.MessageDigest

/** Own the store in a ViewModel or equivalent app lifecycle; this view does not close it. */
@Composable
public fun TetherWorkspace(
    store: TetherConnectionStore,
    modifier: Modifier = Modifier,
    onOpenService: ((String, HostService) -> Unit)? = null,
    onScanInvitation: (suspend () -> String?)? = null,
    hostLabel: (ManagedHost) -> String = ::defaultHostLabel,
) {
    val hosts by store.hosts.collectAsStateWithLifecycle()
    val selected by store.selectedHostId.collectAsStateWithLifecycle()
    var loading by remember(store) { mutableStateOf(true) }
    var busyHosts by remember(store) { mutableStateOf(emptySet<String>()) }
    var problems by remember(store) { mutableStateOf(emptyMap<String, String>()) }
    var loadProblem by remember(store) { mutableStateOf<String?>(null) }
    val operations = remember(store) { mutableMapOf<String, Job>() }
    val scope = rememberCoroutineScope()
    DisposableEffect(store) {
        onDispose {
            operations.values.toList().forEach { it.cancel() }
            operations.clear()
        }
    }
    LaunchedEffect(store) {
        try { store.load() }
        catch (e: CancellationException) { throw e }
        catch (_: Exception) { loadProblem = "Saved hosts could not be loaded. Your saved trust has not been replaced." }
        finally { loading = false }
    }
    fun run(id: String, message: String, action: suspend () -> Unit) {
        if (id in busyHosts) return
        busyHosts = busyHosts + id; problems = problems - id
        val job = scope.launch(start = CoroutineStart.LAZY) {
            try { action() }
            catch (e: CancellationException) { throw e }
            catch (_: Exception) { problems = problems + (id to message) }
            finally { busyHosts = busyHosts - id; operations.remove(id) }
        }
        operations[id] = job; job.start()
    }
    TetherWorkspaceContent(
        appId = store.appId, hosts = hosts, selectedHostId = selected,
        loading = loading, busy = selected in busyHosts, error = problems[selected] ?: loadProblem, modifier = modifier,
        onSelect = { store.selectHost(it) },
        onPair = { route, code -> store.pair(route, code); Unit },
        onConnect = { id -> run(id, "The host could not be reached. Its saved identity is retained.") { store.reconnect(id) } },
        onDisconnect = { id ->
            operations[id]?.cancel()
            scope.launch {
                try { store.disconnect(id) }
                catch (e: CancellationException) { throw e }
                catch (_: Exception) { problems = problems + (id to "The connection could not be closed. Check its current state before retrying.") }
            }
        },
        onLeave = { id -> run(id, "The host did not confirm removal. Its saved identity is retained so you can reconnect and retry.") { store.leave(id) } },
        onForget = { id -> run(id, "Saved trust could not be removed from this device. Try again after the current operation finishes.") { store.forgetLocally(id) } },
        onRecover = { id -> run(id, "The interrupted pairing could not be recovered. Keep its saved record until you can reach the same host.") { store.recover(id) } },
        onDiscardPending = { id -> run(id, "The pending record could not be removed. Try again after the current operation finishes.") { store.discardPending(id) } },
        onOpenService = onOpenService, onScanInvitation = onScanInvitation, hostLabel = hostLabel,
        onChangeRoute = { id, route -> store.changeRoute(id, route) },
    )
}

/** Stateless integration point for app-owned state, navigation and lifecycle. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
public fun TetherWorkspaceContent(
    appId: String,
    hosts: List<ManagedHost>,
    selectedHostId: String?,
    onSelect: (String) -> Unit,
    onPair: suspend (TetherRoute, String) -> Unit,
    onConnect: (String) -> Unit,
    onDisconnect: (String) -> Unit,
    onLeave: (String) -> Unit,
    onForget: (String) -> Unit,
    onRecover: (String) -> Unit,
    onDiscardPending: (String) -> Unit,
    modifier: Modifier = Modifier,
    loading: Boolean = false,
    busy: Boolean = false,
    error: String? = null,
    onOpenService: ((String, HostService) -> Unit)? = null,
    onScanInvitation: (suspend () -> String?)? = null,
    hostLabel: (ManagedHost) -> String = ::defaultHostLabel,
    onChangeRoute: (suspend (String, TetherRoute) -> Unit)? = null,
) {
    var pairing by rememberSaveable { mutableStateOf(false) }
    var detailVisible by rememberSaveable { mutableStateOf(false) }
    var editingRoute by remember { mutableStateOf<ManagedHost?>(null) }
    val selected = hosts.firstOrNull { it.id == selectedHostId }
    LaunchedEffect(selectedHostId) { if (selectedHostId == null) detailVisible = false }
    BoxWithConstraints(modifier.fillMaxSize()) {
        val wide = maxWidth >= 840.dp
        BackHandler(enabled = !wide && detailVisible && !pairing) { detailVisible = false }
        Scaffold(
            topBar = {
                TopAppBar(title = { Text(if (!wide && detailVisible && selected != null) hostLabel(selected) else "Your hosts", maxLines = 2) },
                    navigationIcon = {
                        if (!wide && detailVisible) TextButton(onClick = { detailVisible = false }, modifier = Modifier.testTag("tether.hosts.back")) { Text("Hosts") }
                    },
                    actions = { TextButton(onClick = { pairing = true },
                        modifier = Modifier.testTag("tether.pair")) { Text("Pair host") } })
            },
        ) { insets ->
            Column(Modifier.fillMaxSize().padding(insets)) {
                if (loading || busy) LinearProgressIndicator(Modifier.fillMaxWidth().testTag("tether.operation.progress"))
                error?.let {
                    Text(it, color = MaterialTheme.colorScheme.error,
                        modifier = Modifier.fillMaxWidth().padding(24.dp).testTag("tether.workspace.error")
                            .semantics { liveRegion = LiveRegionMode.Polite })
                }
                Row(Modifier.fillMaxSize()) {
                    if (wide || !detailVisible) {
                        TetherHostList(hosts = hosts, selectedHostId = selectedHostId, loading = loading,
                            onSelect = { onSelect(it); detailVisible = true }, onPair = { pairing = true }, hostLabel = hostLabel,
                            showEmptyAction = !wide, modifier = if (wide) Modifier.width(320.dp).fillMaxHeight() else Modifier.fillMaxSize())
                    }
                    if (wide) VerticalDivider()
                    if (wide || detailVisible) {
                        Box(if (wide) Modifier.weight(1f) else Modifier.fillMaxSize()) {
                            if (selected == null && hosts.isNotEmpty()) {
                                Column(Modifier.padding(24.dp), verticalArrangement = Arrangement.spacedBy(16.dp)) {
                                    Text("Select a host", style = MaterialTheme.typography.headlineSmall)
                                    Text("Choose a saved host to see its current permissions. Selecting a host leaves other hosts’ open streams intact.")
                                }
                            } else if (selected == null) EmptyHosts(onPair = { pairing = true }, waiting = loading)
                            else TetherHostDetail(selected, busy = busy, hostLabel = hostLabel,
                                onConnect = { onConnect(selected.id) }, onDisconnect = { onDisconnect(selected.id) },
                                onLeave = { onLeave(selected.id) }, onForget = { onForget(selected.id) },
                                onRecover = { onRecover(selected.id) }, onDiscardPending = { onDiscardPending(selected.id) },
                                onEditRoute = if (onChangeRoute == null) null else { { editingRoute = selected } },
                                onOpenService = onOpenService?.let { callback -> { service -> callback(selected.id, service) } })
                        }
                    }
                }
            }
        }
    }
    if (pairing) Dialog(onDismissRequest = { pairing = false }, properties = DialogProperties(usePlatformDefaultWidth = false)) {
        Surface(Modifier.fillMaxSize()) {
            TetherPairHost(appId, onPair, onClose = { pairing = false }, onScanInvitation = onScanInvitation)
        }
    }
    editingRoute?.let { host ->
        Dialog(onDismissRequest = { editingRoute = null }, properties = DialogProperties(usePlatformDefaultWidth = false)) {
            Surface(Modifier.fillMaxSize()) {
                TetherRouteEditor(host.record.route, onSave = { route ->
                    require(hosts.firstOrNull { it.id == host.id }?.record == host.record) { "The saved host changed." }
                    onChangeRoute?.invoke(host.id, route)
                }, onClose = { editingRoute = null })
            }
        }
    }
}

/** Embeddable list; keys retain each row's identity across status updates. */
@Composable
public fun TetherHostList(
    hosts: List<ManagedHost>, selectedHostId: String?, onSelect: (String) -> Unit,
    onPair: () -> Unit, modifier: Modifier = Modifier, loading: Boolean = false,
    hostLabel: (ManagedHost) -> String = ::defaultHostLabel, showEmptyAction: Boolean = true,
) {
    if (hosts.isEmpty()) { Box(modifier) { EmptyHosts(onPair, loading, showEmptyAction) }; return }
    LazyColumn(modifier.testTag("tether.hosts")) {
        item { Text("Saved permission and live status are separate.", style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.padding(24.dp)) }
        items(hosts, key = { it.id }) { host ->
            val selected = host.id == selectedHostId
            Surface(onClick = { onSelect(host.id) },
                color = if (selected) MaterialTheme.colorScheme.secondaryContainer else MaterialTheme.colorScheme.surface,
                modifier = Modifier.fillMaxWidth().heightIn(min = 72.dp).testTag("tether.host.${host.id}")
                    .semantics { stateDescription = if (selected) "Selected. ${host.state.displayTitle}" else host.state.displayTitle }) {
                ListItem(headlineContent = { Text(hostLabel(host)) }, supportingContent = { Text(host.state.displayTitle) },
                    colors = ListItemDefaults.colors(containerColor = Color.Transparent))
            }
            HorizontalDivider()
        }
    }
}

@Composable
private fun EmptyHosts(onPair: () -> Unit, waiting: Boolean = false, showAction: Boolean = true) {
    Column(Modifier.fillMaxWidth().padding(24.dp), verticalArrangement = Arrangement.spacedBy(16.dp)) {
        Text(if (waiting) "Reading saved hosts…" else "Connect to your host", style = MaterialTheme.typography.headlineSmall)
        Text(if (waiting) "Saved permissions will appear here. A host is online only after it answers an authenticated connection."
            else "Pair a Mac or Windows PC to use its services in this app. You can keep several hosts paired.",
            color = MaterialTheme.colorScheme.onSurfaceVariant)
        if (!waiting && showAction) Button(onClick = onPair) { Text("Pair host") }
    }
}

@Composable
public fun TetherHostDetail(
    host: ManagedHost,
    onConnect: () -> Unit, onDisconnect: () -> Unit, onLeave: () -> Unit, onForget: () -> Unit,
    onRecover: () -> Unit, onDiscardPending: () -> Unit,
    modifier: Modifier = Modifier, busy: Boolean = false,
    onOpenService: ((HostService) -> Unit)? = null,
    hostLabel: (ManagedHost) -> String = ::defaultHostLabel,
    onEditRoute: (() -> Unit)? = null,
) {
    var removal by remember(host.id) { mutableStateOf<RemovalRequest?>(null) }
    var removalError by remember(host.id) { mutableStateOf<String?>(null) }
    val attention = host.state in setOf(ConnectionState.Revoked, ConnectionState.IdentityMismatch, ConnectionState.Failed)
    Column(modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(24.dp), verticalArrangement = Arrangement.spacedBy(20.dp)) {
        Text(hostLabel(host), style = MaterialTheme.typography.headlineSmall, modifier = Modifier.semantics { heading() })
        removalError?.let { Text(it, color = MaterialTheme.colorScheme.error) }
        Card(colors = CardDefaults.cardColors(containerColor = if (attention) MaterialTheme.colorScheme.errorContainer else MaterialTheme.colorScheme.surfaceContainer),
            modifier = Modifier.fillMaxWidth().testTag("tether.host.status").semantics { liveRegion = LiveRegionMode.Polite }) {
            Column(Modifier.padding(20.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(host.state.displayTitle, style = MaterialTheme.typography.titleMedium)
                Text(host.notice ?: host.state.explanation, style = MaterialTheme.typography.bodyMedium)
            }
        }
        Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text("Connection", style = MaterialTheme.typography.titleSmall)
            Text(when (val route = host.record.route) {
                is TetherRoute.PrivateNetwork -> "Private network or VPN · ${route.host}:${route.port}"
                is TetherRoute.Cloud -> "Cloud relay · ${route.relayUrl}"
            }, style = MaterialTheme.typography.bodyMedium)
            Text("Host identity", style = MaterialTheme.typography.titleSmall)
            SelectionContainer { Text(publicKeyHex(host.record.hostKey), fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodySmall) }
        }
        HorizontalDivider()
        Text("Authorized services", style = MaterialTheme.typography.titleMedium, modifier = Modifier.semantics { heading() })
        if (host.services.isEmpty()) Text(if (host.state == ConnectionState.Connected) "This host grants no services to this device." else "Services appear after an authenticated connection.",
            color = MaterialTheme.colorScheme.onSurfaceVariant)
        host.services.forEach { service ->
            if (onOpenService != null && host.state == ConnectionState.Connected) OutlinedButton(onClick = { onOpenService(service) }, enabled = !busy,
                modifier = Modifier.fillMaxWidth().testTag("tether.service.${service.id}")) { Text("${service.id} · ${service.kind}") }
            else ListItem(headlineContent = { Text(service.id) }, supportingContent = { Text(service.kind.toString()) })
        }
        when (host.state) {
            ConnectionState.Pending -> {
                Button(onRecover, enabled = !busy, modifier = Modifier.fillMaxWidth().testTag("tether.recover")) { Text("Recover pairing") }
                TextButton(onClick = { removalError = null; removal = RemovalRequest(Removal.Discard, host.record) }, enabled = !busy) { Text("Discard pending pairing…") }
            }
            ConnectionState.Connected -> OutlinedButton(onDisconnect, enabled = !busy,
                modifier = Modifier.fillMaxWidth()) { Text("Disconnect") }
            ConnectionState.Connecting -> OutlinedButton(onDisconnect,
                modifier = Modifier.fillMaxWidth().testTag("tether.cancel.connection")) { Text("Cancel connection") }
            ConnectionState.Revoked, ConnectionState.IdentityMismatch -> Unit
            else -> Button(onConnect, enabled = !busy, modifier = Modifier.fillMaxWidth().testTag("tether.reconnect")) { Text("Reconnect") }
        }
        onEditRoute?.let { edit -> OutlinedButton(edit, enabled = !busy, modifier = Modifier.fillMaxWidth().testTag("tether.route.edit")) { Text("Change connection…") } }
        if (host.record.confirmed) OutlinedButton(onClick = { removalError = null; removal = RemovalRequest(Removal.Leave, host.record) }, enabled = !busy && host.state !in setOf(ConnectionState.Revoked, ConnectionState.IdentityMismatch),
            modifier = Modifier.fillMaxWidth().testTag("tether.leave")) { Text("Leave host…") }
        if (host.record.confirmed) TextButton(onClick = { removalError = null; removal = RemovalRequest(Removal.Forget, host.record) }, enabled = !busy,
            modifier = Modifier.fillMaxWidth().testTag("tether.forget")) { Text("Forget locally…") }
    }
    removal?.let { request ->
        val action = request.action
        AlertDialog(onDismissRequest = { removal = null }, title = { Text(action.title) }, text = { Text(action.consequence + "\n\nHost: " + hostLabel(host)) },
            confirmButton = { TextButton(onClick = {
                removal = null
                if (host.record != request.record) removalError = "The saved host changed. Review its current state before trying again."
                else when (action) { Removal.Leave -> onLeave(); Removal.Forget -> onForget(); Removal.Discard -> onDiscardPending() }
            }, modifier = Modifier.testTag("tether.removal.confirm")) { Text(action.action) } },
            dismissButton = { TextButton(onClick = { removal = null }) { Text("Cancel") } })
    }
}

private data class RemovalRequest(val action: Removal, val record: PeerRecord)

private enum class Removal(val title: String, val consequence: String, val action: String) {
    Leave("Leave this host?", "The host will remove this device and close its active streams. Saved trust is removed only after the host confirms. If the host cannot be reached, the record remains for retry.", "Leave host"),
    Forget("Forget this host locally?", "This removes this app’s saved trust on this device and closes its streams. The host is not contacted and may still authorize this device until its owner removes it.", "Forget locally"),
    Discard("Discard pending pairing?", "This removes only the interrupted local record. The host is not contacted. You will need a new owner pairing code to pair again.", "Discard pending"),
}

public val ConnectionState.displayTitle: String get() = when (this) {
    ConnectionState.Offline -> "Offline"
    ConnectionState.Connecting -> "Connecting…"
    ConnectionState.Connected -> "Connected"
    ConnectionState.Pending -> "Pairing interrupted"
    ConnectionState.Revoked -> "Access removed"
    ConnectionState.IdentityMismatch -> "Host identity changed"
    ConnectionState.Capacity -> "Host at capacity"
    ConnectionState.Failed -> "Connection needs attention"
}

private val ConnectionState.explanation: String get() = when (this) {
    ConnectionState.Offline -> "The host has not answered. Its saved identity is retained. Reconnect when it is available."
    ConnectionState.Connecting -> "Checking the saved host’s identity and current permissions."
    ConnectionState.Connected -> "The pinned host authenticated this app’s device and returned its current service permissions."
    ConnectionState.Pending -> "Pairing was interrupted before confirmation. Recover it with the same host before using its services."
    ConnectionState.Revoked -> "The host removed this device’s permission. A new owner pairing code is required to reconnect."
    ConnectionState.IdentityMismatch -> "The endpoint did not match the saved host identity. Saved trust has not been replaced. Check the route with the host’s owner."
    ConnectionState.Capacity -> "The host has no available connection capacity. Close an unused stream or try again later."
    ConnectionState.Failed -> "The connection could not complete. Its saved identity is retained. Check the route and host before retrying."
}

public fun defaultHostLabel(host: ManagedHost): String = when (val route = host.record.route) {
    is TetherRoute.PrivateNetwork -> if (route.host.contains(':')) "[${route.host}]:${route.port}" else "${route.host}:${route.port}"
    is TetherRoute.Cloud -> "Cloud host ${fingerprint(host.record.hostKey)}"
}

private fun publicKeyHex(value: String): String = runCatching {
    Base64.decode(value, Base64.NO_WRAP).joinToString("") { "%02x".format(it.toInt() and 255) }
}.getOrDefault("Identity unavailable")
private fun fingerprint(value: String): String = runCatching {
    MessageDigest.getInstance("SHA-256").digest(Base64.decode(value, Base64.NO_WRAP)).take(8).joinToString("") { "%02x".format(it.toInt() and 255) }
}.getOrDefault("unavailable")
