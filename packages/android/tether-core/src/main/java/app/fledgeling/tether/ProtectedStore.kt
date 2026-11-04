package app.fledgeling.tether

import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.system.Os
import android.util.AtomicFile
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.io.RandomAccessFile
import java.security.KeyStore
import java.security.MessageDigest
import java.util.concurrent.ConcurrentHashMap
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/** App-private, no-backup AES-GCM storage. The Noise identity itself is not a hardware-backed key. */
internal class ProtectedStore(context: Context, private val appId: String, private val allowLoopback: Boolean = false) {
    private val digest = MessageDigest.getInstance("SHA-256").digest((context.packageName + "|" + appId).toByteArray()).joinToString("") { "%02x".format(it) }
    private val folder = File(context.noBackupFilesDir.canonicalFile, "tether-$digest")
    private val file = AtomicFile(File(folder, "trust.bin"))
    private val alias = "tether.v1.$digest"
    private val monitor: Any
    init {
        scope(appId); requireTether(folder.mkdirs() || folder.isDirectory, "storage")
        requireTether(folder.canonicalFile == folder.absoluteFile, "storage"); Os.chmod(folder.path, 448)
        monitor = locks.computeIfAbsent(folder.path) { Any() }
    }
    private fun secret(create: Boolean): SecretKey {
        val keys = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        if (keys.containsAlias(alias)) return keys.getKey(alias, null) as? SecretKey ?: throw TetherException("storage")
        requireTether(create, "storage")
        val spec = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
            .setKeySize(256).setBlockModes(KeyProperties.BLOCK_MODE_GCM).setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setRandomizedEncryptionRequired(true)
        if (Build.VERSION.SDK_INT >= 28) spec.setUnlockedDeviceRequired(true)
        return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").apply { init(spec.build()) }.generateKey()
    }
    private fun read(): JSONObject {
        if (!file.baseFile.exists() && !File(file.baseFile.path + ".bak").exists()) return JSONObject().put("version", 1).put("peers", JSONArray())
        requireTether(file.baseFile.length() <= 131104, "storage")
        val encrypted = file.openRead().use { input -> val buffer=ByteArray(131105); var count=0; while(count<buffer.size) { val n=input.read(buffer,count,buffer.size-count); if(n<0)break; count+=n }; requireTether(count in 29..131104,"storage"); buffer.copyOf(count).also { buffer.fill(0) } }; requireTether(encrypted.size in 29..131104, "storage")
        val cipher = Cipher.getInstance("AES/GCM/NoPadding"); cipher.init(Cipher.DECRYPT_MODE, secret(false), GCMParameterSpec(128, encrypted.copyOfRange(0, 12))); cipher.updateAAD(appId.toByteArray())
        val clear = try { cipher.doFinal(encrypted, 12, encrypted.size - 12) } finally { encrypted.fill(0) }
        try { val data = JSONObject(String(clear, Charsets.UTF_8)); requireTether(data.getInt("version") == 1 && data.getJSONArray("peers").length() <= 256, "storage"); return data } finally { clear.fill(0) }
    }
    private fun write(value: JSONObject) {
        val clear = value.toString().toByteArray(); requireTether(clear.size <= 131072, "storage")
        val cipher = Cipher.getInstance("AES/GCM/NoPadding"); cipher.init(Cipher.ENCRYPT_MODE, secret(true)); cipher.updateAAD(appId.toByteArray())
        val encrypted = try { cipher.iv + cipher.doFinal(clear) } finally { clear.fill(0) }
        val stream = file.startWrite()
        try {
            try { Os.fchmod(stream.fd,384); stream.write(encrypted) } catch(e:Exception) { file.failWrite(stream); throw e }
            // A post-commit error must never run rollback against committed trust.
            file.finishWrite(stream)
        } finally { encrypted.fill(0); runCatching { stream.close() } }
    }
    private fun <T> locked(operation: (JSONObject) -> T): T = synchronized(monitor) {
        try { RandomAccessFile(File(folder, "trust.lock"), "rw").use { lock -> Os.chmod(File(folder, "trust.lock").path, 384); lock.channel.lock().use { operation(read()) } } }
        catch (e: TetherException) { throw e } catch (_: Exception) { throw TetherException("storage") }
    }
    fun identity(): JSONObject = locked { data ->
        if (data.has("identity")) {
            val private = key(data.getString("identity")); try { NativeBridge.invoke("identity.fromPrivate", "private" to b64(private)) } finally { private.fill(0) }
        } else {
            requireTether(data.getJSONArray("peers").length() == 0, "storage")
            val identity = NativeBridge.invoke("identity.generate")
            try { data.put("identity", identity.getString("private")); write(data); identity } catch (e: Exception) { NativeBridge.destroy(identity.getLong("handle")); throw e }
        }
    }
    private fun records(data: JSONObject): List<PeerRecord> {
        val peers = data.getJSONArray("peers"); return (0 until peers.length()).map { PeerRecord.decode(peers.getJSONObject(it)).also { p -> p.validate(appId, allowLoopback) } }.also { requireTether(it.map(PeerRecord::id).distinct().size == it.size, "storage") }
    }
    fun records(): List<PeerRecord> = locked(::records)
    fun matches(peer: PeerRecord): Boolean = locked { records(it).any { p -> p == peer } }
    fun begin(peer: PeerRecord) = locked { data ->
        peer.validate(appId, allowLoopback); val peers = records(data); requireTether(!peer.confirmed && peers.none { it.id == peer.id } && peers.size < 256, "pairing_exists")
        data.put("peers", JSONArray().apply { peers.forEach { put(it.json()) }; put(peer.json()) }); write(data)
    }
    fun replace(expected: PeerRecord, replacement: PeerRecord?): Unit = locked { data ->
        expected.validate(appId, allowLoopback); replacement?.validate(appId, allowLoopback); val peers = records(data)
        requireTether(peers.any { it == expected }, "identity_mismatch")
        requireTether(replacement == null || (replacement.id == expected.id && replacement.clientKey == expected.clientKey), "identity_mismatch")
        data.put("peers", JSONArray().apply { peers.forEach { if (it == expected) { if (replacement != null) put(replacement.json()) } else put(it.json()) } }); write(data)
    }
    companion object { private val locks = ConcurrentHashMap<String, Any>() }
}
