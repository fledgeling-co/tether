package app.fledgeling.tether

import org.json.JSONObject

internal object NativeBridge {
    init { System.loadLibrary("tether_jni") }
    external fun call(request: ByteArray): ByteArray
    fun invoke(command: String, vararg fields: Pair<String, Any>): JSONObject {
        val request = JSONObject().put("command", command); fields.forEach { (k,v) -> request.put(k,v) }
        val input = request.toString().toByteArray(Charsets.UTF_8)
        requireTether(input.size <= 131072, "invalid_frame")
        val output = try { call(input) } finally { input.fill(0) }
        try {
            requireTether(output.size <= 262144)
            val response = JSONObject(String(output, Charsets.UTF_8))
            if (!response.getBoolean("ok")) throw TetherException(response.optString("error", "operation_refused").take(64))
            return response
        } finally { output.fill(0) }
    }
    fun destroy(handle: Long) { if (handle != 0L) runCatching { invoke("destroy", "handle" to handle) } }
}
