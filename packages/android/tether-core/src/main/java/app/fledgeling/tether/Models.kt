package app.fledgeling.tether

import org.json.JSONObject
import java.net.URI
import java.util.Base64
import java.util.UUID

enum class ServiceKind { TCP, UDP }
enum class ConnectionState { Offline, Connecting, Connected, Pending, Revoked, IdentityMismatch, Capacity, Failed }
data class HostService(val id: String, val kind: ServiceKind)
data class HostStatus(val services: List<HostService>)
data class PeerRecord(val appId: String, val hostKey: String, val clientKey: String, val route: TetherRoute, val confirmed: Boolean, val pairingId: String = UUID.randomUUID().toString()) {
    val id: String get() = hostKey
    internal fun validate(expected: String, allowLoopback: Boolean = false) { scope(appId); requireTether(appId == expected, "invalid_scope"); key(hostKey); key(clientKey); requireTether(UUID.fromString(pairingId).toString() == pairingId.lowercase(), "invalid_record"); route.validate(allowLoopback) }
    internal fun json() = JSONObject().put("appId", appId).put("hostKey", hostKey).put("clientKey", clientKey).put("route", route.json()).put("confirmed", confirmed).put("pairingId", pairingId)
    internal companion object { fun decode(value: JSONObject) = PeerRecord(value.getString("appId"), value.getString("hostKey"), value.getString("clientKey"), TetherRoute.decode(value.getJSONObject("route")), value.getBoolean("confirmed"), value.getString("pairingId")) }
}
/** How a nearby pairing ended. Declined and expired save nothing on either device. */
sealed class NearbyOutcome { data class Paired(val record: PeerRecord) : NearbyOutcome(); data object Declined : NearbyOutcome(); data object Expired : NearbyOutcome() }
data class ManagedHost(val record: PeerRecord, val state: ConnectionState, val services: List<HostService> = emptyList(), val notice: String? = null) { val id: String get() = record.id }
class TetherException(val code: String) : Exception(when (code) {
    "identity_mismatch" -> "The host identity changed. Saved trust was retained."
    "peer_revoked" -> "This device's permission was removed at the host."
    "service_capacity", "stream_limit" -> "The host has reached its connection limit."
    "pairing_pending" -> "Pairing needs recovery before services can open."
    "storage" -> "Protected device records could not be read or changed."
    "busy" -> "Another operation is already using this connection."
    "invalid_route" -> "Check the host address and connection details."
    "nearby_closed", "relay_refused" -> "That computer isn't accepting new devices right now."
    "paused" -> "That computer declined this device several times. Try again in 10 minutes."
    "already_paired" -> "This device is already paired with that computer."
    else -> "The secure connection could not complete."
})
internal fun requireTether(ok: Boolean, code: String = "invalid_protocol") { if (!ok) throw TetherException(code) }
internal fun scope(value: String) { requireTether(value.matches(Regex("[A-Za-z0-9._-]{1,64}")), "invalid_scope") }
internal fun key(value: String): ByteArray { val b = try { Base64.getDecoder().decode(value) } catch (_: IllegalArgumentException) { throw TetherException("invalid_record") }; requireTether(b.size == 32 && b64(b) == value, "invalid_record"); return b }
internal fun b64(value: ByteArray): String = Base64.getEncoder().encodeToString(value)
internal fun bytes(value: JSONObject, name: String = "data", size: Int? = null): ByteArray { val b = try { Base64.getDecoder().decode(value.getString(name)) } catch (_: Exception) { throw TetherException("invalid_protocol") }; requireTether(size == null || b.size == size); return b }

sealed class TetherRoute {
    data class PrivateNetwork(val host: String, val port: Int) : TetherRoute()
    data class Cloud(val relayUrl: String, val hostId: String) : TetherRoute()
    fun validate(allowLoopback: Boolean = false) { when (this) {
        is PrivateNetwork -> requireTether(host.isNotEmpty() && host.length <= 320 && host !in listOf("0.0.0.0", "::", "[::]") && host.none { it.isWhitespace() || it in "/?#@" } && port in 1..65535, "invalid_route")
        is Cloud -> { val u = try { URI(relayUrl) } catch (_: Exception) { throw TetherException("invalid_route") }; requireTether(relayUrl.length <= 2048 && !u.host.isNullOrEmpty() && u.rawUserInfo == null && u.rawQuery == null && u.rawFragment == null && (u.port == -1 || u.port in 1..65535) && (u.scheme == "wss" || (allowLoopback && u.scheme == "ws" && u.host in listOf("127.0.0.1", "[::1]", "::1"))) && hostId.matches(Regex("[a-z2-7]{52}")), "invalid_route") }
    } }
    internal fun json(): JSONObject = when (this) { is PrivateNetwork -> JSONObject().put("mode", "private").put("host", host).put("port", port); is Cloud -> JSONObject().put("mode", "cloud").put("relayUrl", relayUrl).put("hostId", hostId) }
    internal companion object { fun decode(j: JSONObject): TetherRoute = when(j.getString("mode")) { "private" -> PrivateNetwork(j.getString("host"), j.getInt("port")); "cloud" -> Cloud(j.getString("relayUrl"), j.getString("hostId")); else -> throw TetherException("invalid_route") } }
}

class TetherPairingInvitation private constructor(val appId: String, val route: TetherRoute, val code: String, val expiresAtEpochMillis: Long) {
    override fun toString() = "TetherPairingInvitation(redacted)"
    companion object {
        fun decode(uri: String, expectedAppId: String, nowEpochMillis: Long = System.currentTimeMillis()): TetherPairingInvitation {
            try {
                requireTether(uri.length <= 4096, "invalid_route"); val u = URI(uri)
                requireTether(u.scheme == "tether" && u.host == "pair" && u.path.isNullOrEmpty() && u.rawUserInfo == null && u.port == -1 && u.rawFragment == null, "invalid_route")
                val query = u.rawQuery ?: throw TetherException("invalid_route")
                requireTether(query.startsWith("data=") && query.count { it == '=' } == 1, "invalid_route")
                val raw = query.removePrefix("data="); requireTether(raw.length <= 3500 && raw.matches(Regex("[A-Za-z0-9_-]+")), "invalid_route")
                val j = JSONObject(String(Base64.getUrlDecoder().decode(raw), Charsets.UTF_8)); val app = j.getString("appID"); scope(app)
                val code = j.getString("code"); requireTether(j.getInt("version") == 1 && app == expectedAppId && code.matches(Regex("[0123456789ABCDEFGHJKMNPQRSTVWXYZ]{8}")))
                val expirySeconds = j.getDouble("expiresAt") + 978307200.0
                requireTether(expirySeconds.isFinite() && expirySeconds * 1000 > nowEpochMillis && expirySeconds * 1000 - nowEpochMillis <= 301000)
                val routeJSON = j.getJSONObject("route")
                val route = when { routeJSON.has("privateNetwork") -> routeJSON.getJSONObject("privateNetwork").let { TetherRoute.PrivateNetwork(it.getString("host"), it.getInt("port")) }; routeJSON.has("cloud") -> routeJSON.getJSONObject("cloud").let { TetherRoute.Cloud(it.getString("relayURL"), it.getString("hostID")) }; else -> throw TetherException("invalid_route") }
                route.validate(); return TetherPairingInvitation(app, route, code, (expirySeconds * 1000).toLong())
            } catch (e: TetherException) { throw e } catch (_: Exception) { throw TetherException("invalid_route") }
        }
    }
}
