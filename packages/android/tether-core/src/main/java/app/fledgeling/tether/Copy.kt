package app.fledgeling.tether

import org.json.JSONObject

/** A button as the Rust core describes it. */
data class TetherButtonModel(val label: String, val enabled: Boolean)
/** Six digits for display: two groups, and a version read aloud digit by digit. */
data class TetherCodeModel(val digits: String, val groups: List<String>, val spoken: String)
/** The requesting device's nearby sheet. `tone` is neutral, success or warning. */
data class TetherNearbyViewModel(val phase: String, val title: String, val message: String, val tone: String, val note: String?, val code: TetherCodeModel?,
    val expiry: String?, val primary: TetherButtonModel?, val secondary: TetherButtonModel?, val announce: Boolean, val busy: Boolean)
/** The host owner's request sheet. */
data class TetherHostRequestViewModel(val title: String, val code: TetherCodeModel, val message: String, val services: String?, val note: String?,
    val expiry: String, val primary: TetherButtonModel, val secondary: TetherButtonModel)
/** A saved host's connection state. `tone` is neutral, success, warning or danger. */
data class TetherConnectionStateModel(val state: String, val title: String, val explanation: String, val tone: String)

/** The words every Tether screen uses, from the Rust core, so Compose says what Swift, WinUI and the web say. */
object TetherCopy {
    private fun JSONObject.text(key: String): String? = if (isNull(key)) null else optString(key)
    private fun button(j: JSONObject?): TetherButtonModel? = j?.let { TetherButtonModel(it.getString("label"), it.getBoolean("enabled")) }
    private fun code(j: JSONObject?): TetherCodeModel? = j?.let { c -> TetherCodeModel(c.getString("digits"), List(c.getJSONArray("groups").length()) { c.getJSONArray("groups").getString(it) }, c.getString("spoken")) }

    /** The sheet for [state]; [device] is what this device is called in copy ("phone"). */
    fun nearby(state: NearbyPairingState, device: String, canApprove: Boolean, nowMillis: Long = System.currentTimeMillis()): TetherNearbyViewModel? {
        val fields: List<Pair<String, Any>> = when (state) {
            NearbyPairingState.Idle -> return null
            is NearbyPairingState.Checking -> listOf("phase" to "checking", "peer" to state.peer)
            is NearbyPairingState.Code -> listOf("phase" to "code", "peer" to state.peer, "incoming" to state.incoming, "code" to state.code,
                "remainingMs" to (state.expiresAtMillis - nowMillis).coerceAtLeast(0), "canApprove" to canApprove, "hostApproved" to state.otherApproved)
            is NearbyPairingState.Waiting -> listOf("phase" to "waiting", "peer" to state.peer, "code" to state.code)
            is NearbyPairingState.Storing -> listOf("phase" to "storing", "peer" to state.peer, "code" to state.code)
            is NearbyPairingState.Connected -> listOf("phase" to "connected", "peer" to state.peer)
            is NearbyPairingState.Declined -> listOf("phase" to "declined", "peer" to state.peer, "declinedBySelf" to !state.byOther)
            is NearbyPairingState.Expired -> listOf("phase" to "expired", "peer" to state.peer)
            is NearbyPairingState.Failed -> listOf("phase" to "failed", "peer" to state.peer)
        }
        val j = NativeBridge.invoke("ui.nearby", "device" to device, *fields.toTypedArray())
        // A failure's explanation was worked out from the error when it happened.
        val message = (state as? NearbyPairingState.Failed)?.message ?: j.getString("message")
        return TetherNearbyViewModel(j.getString("phase"), j.getString("title"), message, j.getString("tone"), j.text("note"), code(j.optJSONObject("code")),
            j.text("expiry"), button(j.optJSONObject("primary")), button(j.optJSONObject("secondary")), j.getBoolean("announce"), j.getBoolean("busy"))
    }

    fun hostRequest(name: String, code: String, remainingMs: Long, shownMs: Long, deviceApproved: Boolean, invited: Boolean, services: List<String>): TetherHostRequestViewModel {
        val j = NativeBridge.invoke("ui.host_request", "name" to name, "code" to code, "remainingMs" to remainingMs.coerceAtLeast(0), "shownMs" to shownMs.coerceAtLeast(0),
            "deviceApproved" to deviceApproved, "invited" to invited, "services" to org.json.JSONArray(services))
        return TetherHostRequestViewModel(j.getString("title"), code(j.getJSONObject("code"))!!, j.getString("message"), j.text("services"), j.text("note"),
            j.getString("expiry"), button(j.getJSONObject("primary"))!!, button(j.getJSONObject("secondary"))!!)
    }

    fun connectionState(state: String): TetherConnectionStateModel {
        val j = NativeBridge.invoke("ui.connection_state", "state" to state)
        return TetherConnectionStateModel(j.getString("state"), j.getString("title"), j.getString("explanation"), j.getString("tone"))
    }

    private val cache = java.util.concurrent.ConcurrentHashMap<String, Map<String, String>>()
    /** Fixed copy keyed as in the core's `view::strings`; a missing key reads as itself. */
    fun text(key: String, device: String = "device"): String = cache.getOrPut(device) {
        val j = NativeBridge.invoke("ui.strings", "device" to device); j.keys().asSequence().filter { it != "ok" }.associateWith { j.getString(it) }
    }[key] ?: key

    /** A plain-language explanation of a failure code, naming [peer]. */
    fun message(code: String, peer: String): String = runCatching { NativeBridge.invoke("ui.error", "code" to code, "peer" to peer).getString("message") }
        .getOrDefault("The pairing didn't finish. Nothing was paired.")

    /** A label another device chose, safe to show beside a code. */
    fun label(raw: String?, fallback: String): String = runCatching { NativeBridge.invoke("ui.label", "text" to (raw ?: ""), "fallback" to fallback).getString("text") }
        .getOrDefault(fallback)
}
