package app.fledgeling.tether

import android.content.Context
import android.net.nsd.NsdManager
import android.net.nsd.NsdServiceInfo
import android.os.Build
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.io.Closeable
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.Executors

/** Bonjour types shared with the Apple and Windows kits: hosts announce their direct port; devices announce an invite listener. */
object TetherNearbyService { const val HOST = "_tether._tcp"; const val DEVICE = "_tether-dev._tcp" }

/** Something announcing this app on the local network. Its name is a label shown beside the code, never trusted on its own. */
data class NearbyPeer(val id: String, val name: String, val kind: String, val hostKey: String?, val addresses: List<String>, val port: Int)

enum class NearbyBrowseState { Searching, Ready, Failed }

internal fun nearbyLabel(raw: String?, fallback: String): String {
    val cleaned = (raw ?: "").filter { c -> !c.isISOControl() && c.code !in 0x200B..0x200F && c.code !in 0x202A..0x202E && c.code !in 0x2066..0x2069 }.trim().take(48)
    return cleaned.ifEmpty { fallback }
}

/** Lists hosts (or, on a host, devices) announcing this app, resolving each to its addresses and TXT record. */
class TetherNearbyBrowser(context: Context, val appId: String, private val serviceType: String = TetherNearbyService.HOST) : Closeable {
    private val nsd = context.applicationContext.getSystemService(Context.NSD_SERVICE) as NsdManager
    private val executor = Executors.newSingleThreadExecutor()
    private val found = mutableMapOf<String, NearbyPeer>()
    private val mutablePeers = MutableStateFlow<List<NearbyPeer>>(emptyList()); val peers: StateFlow<List<NearbyPeer>> = mutablePeers.asStateFlow()
    private val mutableState = MutableStateFlow(NearbyBrowseState.Searching); val state: StateFlow<NearbyBrowseState> = mutableState.asStateFlow()
    private var listener: NsdManager.DiscoveryListener? = null

    init { scope(appId) }

    fun start() {
        if (listener != null) return
        val discovery = object : NsdManager.DiscoveryListener {
            override fun onDiscoveryStarted(type: String) { mutableState.value = NearbyBrowseState.Ready }
            override fun onDiscoveryStopped(type: String) {}
            override fun onStartDiscoveryFailed(type: String, error: Int) { mutableState.value = NearbyBrowseState.Failed }
            override fun onStopDiscoveryFailed(type: String, error: Int) {}
            override fun onServiceFound(info: NsdServiceInfo) { resolve(info) }
            override fun onServiceLost(info: NsdServiceInfo) { synchronized(found) { found.remove(info.serviceName); publish() } }
        }
        listener = discovery
        nsd.discoverServices(serviceType, NsdManager.PROTOCOL_DNS_SD, discovery)
    }

    @Suppress("DEPRECATION")
    private fun resolve(info: NsdServiceInfo) {
        val accept: (NsdServiceInfo) -> Unit = { resolved ->
            val txt = resolved.attributes.mapValues { (_, v) -> v?.toString(Charsets.UTF_8) }
            if (txt["app"] == appId) {
                val hinted = (txt["addr"] ?: "").split(',').filter { it.matches(Regex("""\d{1,3}(\.\d{1,3}){3}""")) }.take(8)
                val resolvedAddress = if (Build.VERSION.SDK_INT >= 34) resolved.hostAddresses.map { it.hostAddress } else listOfNotNull(resolved.host?.hostAddress)
                val port = txt["port"]?.toIntOrNull()?.takeIf { it in 1..65535 } ?: resolved.port
                val peer = NearbyPeer(resolved.serviceName, nearbyLabel(txt["name"] ?: resolved.serviceName, resolved.serviceName), nearbyLabel(txt["kind"], "Computer"),
                    txt["key"]?.takeIf { runCatching { key(it) }.isSuccess }, (hinted + resolvedAddress.filterNotNull()).distinct(), port)
                synchronized(found) { found[peer.id] = peer; publish() }
            }
        }
        if (Build.VERSION.SDK_INT >= 34) {
            nsd.registerServiceInfoCallback(info, executor, object : NsdManager.ServiceInfoCallback {
                override fun onServiceInfoCallbackRegistrationFailed(error: Int) {}
                override fun onServiceUpdated(resolved: NsdServiceInfo) { accept(resolved) }
                override fun onServiceLost() { synchronized(found) { found.remove(info.serviceName); publish() } }
                override fun onServiceInfoCallbackUnregistered() {}
            })
        } else {
            nsd.resolveService(info, object : NsdManager.ResolveListener {
                override fun onResolveFailed(info: NsdServiceInfo, error: Int) {}
                override fun onServiceResolved(resolved: NsdServiceInfo) { accept(resolved) }
            })
        }
    }

    private fun publish() { mutablePeers.value = found.values.sortedBy { it.name.lowercase() } }

    override fun close() { listener?.let { runCatching { nsd.stopServiceDiscovery(it) } }; listener = null; executor.shutdown() }

    companion object {
        /** The first announced address that accepts a TCP connection within a moment. */
        suspend fun route(peer: NearbyPeer): TetherRoute = withContext(Dispatchers.IO) {
            for (address in peer.addresses) {
                val reachable = runCatching { Socket().use { it.connect(InetSocketAddress(address, peer.port), 1500) } }.isSuccess
                if (reachable) return@withContext TetherRoute.PrivateNetwork(address, peer.port)
            }
            throw TetherException("invalid_route")
        }
    }
}

/** An invitation a host sent: connect to this route and pair. */
data class NearbyInvite(val route: TetherRoute, val hostName: String)

/** This device's invite listener, announced while "Add a computer" is open. An invite only starts an ordinary nearby pairing to
 *  the inviting address; the code comparison still decides trust. */
class TetherNearbyInviteListener(context: Context, appId: String, deviceName: String, deviceKind: String, onInvite: (NearbyInvite) -> Unit) : Closeable {
    private val nsd = context.applicationContext.getSystemService(Context.NSD_SERVICE) as NsdManager
    private val server = ServerSocket(0)
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val registration = object : NsdManager.RegistrationListener {
        override fun onServiceRegistered(info: NsdServiceInfo) {}
        override fun onRegistrationFailed(info: NsdServiceInfo, error: Int) {}
        override fun onServiceUnregistered(info: NsdServiceInfo) {}
        override fun onUnregistrationFailed(info: NsdServiceInfo, error: Int) {}
    }

    init {
        scope(appId)
        val info = NsdServiceInfo().apply {
            serviceName = nearbyLabel(deviceName, "Device"); serviceType = TetherNearbyService.DEVICE; port = server.localPort
            setAttribute("app", appId); setAttribute("name", nearbyLabel(deviceName, "Device")); setAttribute("kind", nearbyLabel(deviceKind, "Device"))
        }
        nsd.registerService(info, NsdManager.PROTOCOL_DNS_SD, registration)
        scope.launch {
            while (!server.isClosed) {
                val socket = runCatching { server.accept() }.getOrNull() ?: break
                launch {
                    socket.use {
                        it.soTimeout = 3000
                        val line = runCatching { it.getInputStream().bufferedReader().readLine() }.getOrNull()?.take(512) ?: return@use
                        val json = runCatching { JSONObject(line) }.getOrNull() ?: return@use
                        val port = json.optInt("port", 0)
                        val host = it.inetAddress?.hostAddress ?: return@use
                        if (json.optInt("v") == 1 && json.optString("app") == appId && port in 1..65535)
                            onInvite(NearbyInvite(TetherRoute.PrivateNetwork(host, port), nearbyLabel(json.optString("name"), "Computer")))
                    }
                }
            }
        }
    }

    override fun close() { runCatching { nsd.unregisterService(registration) }; runCatching { server.close() }; scope.cancel() }
}

/** Where a nearby pairing stands, for the device's sheet. */
sealed class NearbyPairingState {
    data object Idle : NearbyPairingState()
    data class Checking(val peer: String) : NearbyPairingState()
    data class Code(val code: String, val peer: String, val incoming: Boolean, val expiresAtMillis: Long, val otherApproved: Boolean) : NearbyPairingState()
    data class Waiting(val code: String, val peer: String) : NearbyPairingState()
    /** Both approved and the acknowledgement is going out; it can no longer be cancelled. */
    data class Storing(val code: String, val peer: String) : NearbyPairingState()
    data class Connected(val peer: String, val hostId: String) : NearbyPairingState()
    data class Declined(val peer: String, val byOther: Boolean) : NearbyPairingState()
    data class Expired(val peer: String) : NearbyPairingState()
    data class Failed(val peer: String, val message: String) : NearbyPairingState()
    val isActive: Boolean get() = this is Checking || this is Code || this is Waiting || this is Storing
}

/** Runs one nearby pairing at a time against a connection store. */
class TetherNearbyPairing(private val store: TetherConnectionStore, private val deviceName: String, private val deviceKind: String) : Closeable {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)
    private val mutableState = MutableStateFlow<NearbyPairingState>(NearbyPairingState.Idle); val state: StateFlow<NearbyPairingState> = mutableState.asStateFlow()
    @Volatile private var answer: Boolean? = null
    @Volatile private var shownAt = 0L
    private var job: Job? = null

    fun start(peer: NearbyPeer) = begin(peer.name, false) { TetherNearbyBrowser.route(peer) }
    fun accept(invite: NearbyInvite) { if (!state.value.isActive) begin(invite.hostName, true) { invite.route } }

    private fun begin(peerName: String, incoming: Boolean, route: suspend () -> TetherRoute) {
        if (state.value.isActive) return
        answer = null; shownAt = 0L; mutableState.value = NearbyPairingState.Checking(peerName)
        job = scope.launch {
            mutableState.value = try {
                val outcome = store.pairNearby(route(), deviceName, deviceKind,
                    onCode = { code -> shownAt = System.currentTimeMillis(); mutableState.value = NearbyPairingState.Code(code, peerName, incoming, shownAt + 60_000, false) },
                    onHostApproved = { (mutableState.value as? NearbyPairingState.Code)?.let { mutableState.value = it.copy(otherApproved = true) } },
                    decision = { answer },
                    onStoring = { (mutableState.value as? NearbyPairingState.Waiting)?.let { mutableState.value = NearbyPairingState.Storing(it.code, it.peer) } })
                when (outcome) {
                    is NearbyOutcome.Paired -> NearbyPairingState.Connected(peerName, outcome.record.id)
                    NearbyOutcome.Declined -> NearbyPairingState.Declined(peerName, answer != false)
                    NearbyOutcome.Expired -> NearbyPairingState.Expired(peerName)
                }
            } catch (e: kotlinx.coroutines.CancellationException) { NearbyPairingState.Idle
            } catch (e: TetherException) { NearbyPairingState.Failed(peerName, TetherCopy.message(e.code, peerName))
            } catch (e: Exception) { NearbyPairingState.Failed(peerName, TetherCopy.message("connection_closed", peerName)) }
        }
    }

    /** Approve counts only once the code has been on screen for a second. */
    val canApprove: Boolean get() = shownAt > 0 && System.currentTimeMillis() - shownAt >= 1000
    fun approve() { val s = state.value as? NearbyPairingState.Code ?: return; if (!canApprove) return; answer = true; mutableState.value = NearbyPairingState.Waiting(s.code, s.peer) }
    fun decline() { answer = false }
    fun reset() { job?.cancel(); job = null; answer = null; shownAt = 0L; mutableState.value = NearbyPairingState.Idle }
    override fun close() { scope.cancel() }
}
