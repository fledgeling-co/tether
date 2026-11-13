package app.fledgeling.tether.ui

import app.fledgeling.tether.TetherCopy

import android.os.Build
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.ListItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import app.fledgeling.tether.NearbyPairingState
import app.fledgeling.tether.NearbyPeer
import app.fledgeling.tether.TetherConnectionStore
import app.fledgeling.tether.TetherNearbyBrowser
import app.fledgeling.tether.TetherNearbyInviteListener
import app.fledgeling.tether.TetherNearbyPairing
import app.fledgeling.tether.TetherRoute
import kotlinx.coroutines.delay

/** The six digits as two groups of three tiles, read digit by digit by TalkBack. */
@Composable
public fun TetherNearbyCodeTiles(code: String, modifier: Modifier = Modifier) {
    val spoken = code.take(3).toList().joinToString(" ") + ", " + code.drop(3).toList().joinToString(" ")
    Row(modifier.semantics(mergeDescendants = true) { contentDescription = "Code $spoken" }.testTag("tether.nearby.code"),
        horizontalArrangement = Arrangement.spacedBy(6.dp), verticalAlignment = Alignment.CenterVertically) {
        code.forEachIndexed { index, digit ->
            if (index == 3) Spacer(Modifier.width(10.dp))
            Box(Modifier.size(width = 44.dp, height = 56.dp).background(MaterialTheme.colorScheme.surface, RoundedCornerShape(12.dp))
                .border(BorderStroke(1.dp, MaterialTheme.colorScheme.outlineVariant), RoundedCornerShape(12.dp)), contentAlignment = Alignment.Center) {
                Text(digit.toString(), fontFamily = FontFamily.Monospace, fontSize = 30.sp, fontWeight = FontWeight.Medium)
            }
        }
    }
}

/** "Add a computer": computers announcing this app nearby, the code comparison, and the typed-code route for relay pairing. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
public fun TetherNearbyPair(
    store: TetherConnectionStore,
    onPair: suspend (TetherRoute, String) -> Unit,
    onClose: () -> Unit,
    modifier: Modifier = Modifier,
    deviceName: String = Build.MODEL,
    deviceKind: String = "Android",
    title: String = "Add a computer",
    onScanInvitation: (suspend () -> String?)? = null,
) {
    val context = LocalContext.current
    val browser = remember(store) { TetherNearbyBrowser(context, store.appId) }
    val pairing = remember(store) { TetherNearbyPairing(store, deviceName, deviceKind) }
    val peers by browser.peers.collectAsStateWithLifecycle()
    val hosts by store.hosts.collectAsStateWithLifecycle()
    val state by pairing.state.collectAsStateWithLifecycle()
    var settled by remember { mutableStateOf(false) }
    var manual by remember { mutableStateOf(false) }
    DisposableEffect(browser, pairing) {
        browser.start()
        val listener = runCatching { TetherNearbyInviteListener(context, store.appId, deviceName, deviceKind) { invite -> pairing.accept(invite) } }.getOrNull()
        onDispose { browser.close(); listener?.close(); pairing.reset(); pairing.close() }
    }
    LaunchedEffect(Unit) { delay(2000); settled = true }
    Scaffold(modifier, topBar = { TopAppBar(title = { Text(title) }, navigationIcon = { TextButton(onClick = { pairing.reset(); onClose() }) { Text("Close") } }) }) { padding ->
        LazyColumn(Modifier.fillMaxSize().padding(padding).testTag("tether.nearby.list")) {
            item {
                Text(TetherCopy.text("section"), style = MaterialTheme.typography.titleSmall, color = MaterialTheme.colorScheme.primary, modifier = Modifier.padding(start = 16.dp, top = 16.dp, bottom = 8.dp))
                LinearProgressIndicator(Modifier.fillMaxWidth().padding(horizontal = 16.dp).semantics { contentDescription = "Searching" })
            }
            if (peers.isEmpty() && settled) item {
                Column(Modifier.fillMaxWidth().padding(24.dp), horizontalAlignment = Alignment.CenterHorizontally) {
                    Text(TetherCopy.text("empty_title"), style = MaterialTheme.typography.titleMedium)
                    Text(TetherCopy.text("empty_message"), textAlign = TextAlign.Center, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
            }
            items(peers, key = { it.id }) { peer -> PeerRow(peer, paired = hosts.any { it.record.hostKey == peer.hostKey }, enabled = !state.isActive) {
                val existing = hosts.firstOrNull { it.record.hostKey == peer.hostKey }
                if (existing != null) { store.selectHost(existing.id); onClose() } else pairing.start(peer)
            } }
            item {
                Text(TetherCopy.text("footer"),
                    style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.padding(16.dp))
                OutlinedButton(onClick = { manual = true }, modifier = Modifier.padding(horizontal = 16.dp).testTag("tether.nearby.manual")) { Text(TetherCopy.text("manual")) }
                Text(TetherCopy.text("manual_footer"),
                    style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.padding(16.dp))
            }
        }
    }
    if (state != NearbyPairingState.Idle) {
        ModalBottomSheet(onDismissRequest = { if (state.isActive) pairing.decline() else pairing.reset() }, sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)) {
            TetherNearbyConfirm(state, pairing, onDone = { if (state is NearbyPairingState.Connected) { pairing.reset(); onClose() } else pairing.reset() }, device = if (deviceKind == "Android") "phone" else deviceKind)
        }
    }
    if (manual) Dialog(onDismissRequest = { manual = false }, properties = DialogProperties(usePlatformDefaultWidth = false)) {
        Surface(Modifier.fillMaxSize()) { TetherPairHost(store.appId, onPair, onClose = { manual = false }, onScanInvitation = onScanInvitation) }
    }
}

@Composable
private fun PeerRow(peer: NearbyPeer, paired: Boolean, enabled: Boolean, onClick: () -> Unit) {
    ListItem(
        headlineContent = { Text(peer.name) },
        supportingContent = { Text(if (paired) TetherCopy.text("paired") else peer.kind) },
        modifier = Modifier.clickable(enabled = enabled, onClick = onClick).testTag("tether.nearby.peer.${peer.name}"),
    )
}

/** The device's confirmation, waiting and result states. */
@Composable
public fun TetherNearbyConfirm(state: NearbyPairingState, pairing: TetherNearbyPairing, onDone: () -> Unit, device: String = "device") {
    var tick by remember { mutableIntStateOf(0) }
    LaunchedEffect(state) { while (true) { delay(250); tick++ } }
    Column(Modifier.fillMaxWidth().padding(horizontal = 24.dp).padding(bottom = 32.dp), horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(16.dp)) {
        // The core decides the words and when Approve is enabled; the tick keeps the countdown current.
        val view = remember(state, tick) { TetherCopy.nearby(state, device, pairing.canApprove) } ?: return@Column
        val peerCode = (state as? NearbyPairingState.Code)?.code ?: (state as? NearbyPairingState.Waiting)?.code ?: (state as? NearbyPairingState.Storing)?.code
        when (view.phase) {
            "checking" -> Text(view.title)
            "code" -> {
                Text(view.title, style = MaterialTheme.typography.headlineSmall, textAlign = TextAlign.Center)
                peerCode?.let { TetherNearbyCodeTiles(it) }
                Text(view.message, textAlign = TextAlign.Center, color = MaterialTheme.colorScheme.onSurfaceVariant)
                view.note?.let { Text(it, color = MaterialTheme.colorScheme.onSurfaceVariant) }
                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.End) {
                    view.secondary?.let { TextButton(onClick = { pairing.decline() }, modifier = Modifier.testTag("tether.nearby.decline")) { Text(it.label) } }
                    Spacer(Modifier.width(8.dp))
                    view.primary?.let { Button(onClick = { pairing.approve() }, enabled = it.enabled, modifier = Modifier.testTag("tether.nearby.approve")) { Text(it.label) } }
                }
                view.expiry?.let { Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant) }
            }
            "waiting", "storing" -> {
                Text(view.title, style = MaterialTheme.typography.headlineSmall)
                peerCode?.let { TetherNearbyCodeTiles(it) }
                Text(view.message, modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite })
                view.secondary?.let { OutlinedButton(onClick = { pairing.decline() }, enabled = it.enabled) { Text(it.label) } }
            }
            "connected" -> {
                LaunchedEffect(state) { delay(1200); onDone() }
                Result(view.title, view.message)
            }
            else -> { Result(view.title, view.message); Button(onClick = onDone) { Text(view.primary?.label ?: "Done") } }
        }
    }
}

@Composable
private fun Result(title: String, detail: String) {
    Column(Modifier.semantics(mergeDescendants = true) { liveRegion = LiveRegionMode.Polite }, horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Text(title, style = MaterialTheme.typography.headlineSmall, textAlign = TextAlign.Center)
        Text(detail, textAlign = TextAlign.Center, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Spacer(Modifier.height(4.dp))
    }
}
