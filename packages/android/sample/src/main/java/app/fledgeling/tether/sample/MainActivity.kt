package app.fledgeling.tether.sample

import android.app.Application
import android.content.pm.ActivityInfo
import android.content.res.Configuration
import android.graphics.Color
import android.os.Bundle
import android.util.Base64
import androidx.activity.ComponentActivity
import androidx.activity.SystemBarStyle
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewmodel.compose.viewModel
import app.fledgeling.tether.ConnectionState
import app.fledgeling.tether.HostService
import app.fledgeling.tether.ServiceKind
import app.fledgeling.tether.ManagedHost
import app.fledgeling.tether.PeerRecord
import app.fledgeling.tether.TetherClient
import app.fledgeling.tether.TetherConnectionStore
import app.fledgeling.tether.TetherRoute
import app.fledgeling.tether.ui.TetherWorkspace
import app.fledgeling.tether.ui.TetherWorkspaceContent
import java.util.UUID

public class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // Debug-only fixtures never construct a real client or access Android Keystore.
        val fixtures = BuildConfig.DEBUG && intent.getBooleanExtra("tether.designFixtures", false)
        val darkAppearance = if (fixtures) intent.getBooleanExtra("tether.dark", false)
            else resources.configuration.uiMode and Configuration.UI_MODE_NIGHT_MASK == Configuration.UI_MODE_NIGHT_YES
        val bars = if (darkAppearance) SystemBarStyle.dark(Color.TRANSPARENT)
            else SystemBarStyle.light(Color.TRANSPARENT, Color.TRANSPARENT)
        enableEdgeToEdge(statusBarStyle = bars, navigationBarStyle = bars)
        if (fixtures) {
            requestedOrientation = if (intent.getBooleanExtra("tether.landscape", false))
                ActivityInfo.SCREEN_ORIENTATION_LANDSCAPE else ActivityInfo.SCREEN_ORIENTATION_PORTRAIT
        }
        setContent {
            val dark = if (fixtures) intent.getBooleanExtra("tether.dark", false) else isSystemInDarkTheme()
            MaterialTheme(colorScheme = if (dark) darkColorScheme() else lightColorScheme()) {
                Surface(Modifier.fillMaxSize()) {
                    if (fixtures) FixtureWorkspace(intent.getBooleanExtra("tether.allStates", false))
                    else {
                        val model: TetherSampleModel = viewModel()
                        model.connections?.let { TetherWorkspace(it) } ?: Column(Modifier.padding(24.dp)) {
                            Text("Workspace unavailable", style = MaterialTheme.typography.headlineSmall)
                            Text("The secure transport could not initialize. Saved trust has not been replaced.")
                        }
                    }
                }
            }
        }
    }
}

/** The application owns the transport; recomposition and navigation do not destroy open streams. */
public class TetherSampleModel(application: Application) : AndroidViewModel(application) {
    private val client = runCatching { TetherClient(application, "app.fledgeling.tether.sample") }.getOrNull()
    public val connections: TetherConnectionStore? = client?.let { TetherConnectionStore(it) }
    override fun onCleared() { connections?.close(); client?.close() }
}

@Composable
private fun FixtureWorkspace(allStates: Boolean) {
    val hosts = remember(allStates) {
        val states = listOf(ConnectionState.Offline, ConnectionState.Revoked, ConnectionState.IdentityMismatch) +
            if (allStates) listOf(ConnectionState.Connecting, ConnectionState.Pending, ConnectionState.Connected, ConnectionState.Capacity, ConnectionState.Failed) else emptyList()
        states.mapIndexed { offset, state ->
            val index = offset + 1
            ManagedHost(PeerRecord("app.fledgeling.tether.sample",
                Base64.encodeToString(ByteArray(32) { index.toByte() }, Base64.NO_WRAP),
                Base64.encodeToString(ByteArray(32) { 7 }, Base64.NO_WRAP),
                TetherRoute.PrivateNetwork("studio-$index.local", 9000), state != ConnectionState.Pending, UUID.randomUUID().toString()), state,
                services = if (state == ConnectionState.Connected) listOf(HostService("application-api", ServiceKind.TCP), HostService("media", ServiceKind.UDP)) else emptyList())
        }
    }
    var selected by remember { mutableStateOf<String?>(hosts.first().id) }
    var message by remember { mutableStateOf<String?>(null) }
    Column(Modifier.fillMaxSize().safeDrawingPadding()) {
        Text("Design fixtures · No network connection", style = MaterialTheme.typography.labelMedium,
            modifier = Modifier.fillMaxWidth().padding(12.dp))
        TetherWorkspaceContent(
            appId = "app.fledgeling.tether.sample", hosts = hosts, selectedHostId = selected,
            onSelect = { selected = it }, onPair = { _, _ -> error("Fixture cannot pair") },
            onConnect = { message = "This is a design fixture. No connection was attempted." },
            onDisconnect = { message = "This is a design fixture. No connection was closed." },
            onLeave = { message = "This is a design fixture. No host permission was changed." },
            onForget = { message = "This is a design fixture. No saved trust was removed." },
            onRecover = { message = "This is a design fixture. No pairing was recovered." },
            onDiscardPending = { message = "This is a design fixture. No record was removed." },
            modifier = Modifier.weight(1f), error = message,
            onChangeRoute = { _, _ -> error("Fixture cannot change routes") },
        )
    }
}
