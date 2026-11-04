package app.fledgeling.tether

import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.ext.junit.runners.AndroidJUnit4
import kotlinx.coroutines.*
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.security.KeyStore
import java.security.MessageDigest
import java.util.UUID

@RunWith(AndroidJUnit4::class)
class CoreInstrumentationTest {
    @Test fun nativeNoisePakeAndBoundedJni() {
        val handles=mutableListOf<Long>()
        fun call(command:String,vararg fields:Pair<String,Any>):JSONObject=NativeBridge.invoke(command,*fields).also { if(it.has("handle"))handles.add(it.getLong("handle")) }
        try {
            val client=call("identity.generate"); val host=call("identity.generate")
            val c=call("noise.new","identity" to client.getLong("handle"),"app" to "app.tether.android-test","role" to "client").getLong("handle")
            val h=call("noise.new","identity" to host.getLong("handle"),"app" to "app.tether.android-test","role" to "host").getLong("handle")
            call("noise.read","handle" to h,"data" to call("noise.write","handle" to c,"data" to "").getString("data"))
            val meta=call("noise.read","handle" to c,"data" to call("noise.write","handle" to h,"data" to "").getString("data")); assertTrue(bytes(meta,"remoteStatic",32).contentEquals(bytes(host,"public",32)))
            call("noise.read","handle" to h,"data" to call("noise.write","handle" to c,"data" to "").getString("data")); val ct=call("noise.finish","handle" to c); val ht=call("noise.finish","handle" to h)
            assertTrue(bytes(ct,"binding",32).contentEquals(bytes(ht,"binding",32)))
            val clear=ByteArray(16384){(it%251).toByte()}; val encrypted=call("transport.encrypt","handle" to ct.getLong("handle"),"data" to b64(clear)); val decrypted=call("transport.decrypt","handle" to ht.getLong("handle"),"data" to encrypted.getString("data")); assertTrue(clear.contentEquals(bytes(decrypted)))
            try { call("transport.decrypt","handle" to ht.getLong("handle"),"data" to encrypted.getString("data")); fail("Replay accepted") } catch(_:TetherException) { }
            fun pairing(code:String,role:String)=call("pairing.start","role" to role,"code" to code,"app" to "app.tether.android-test","binding" to ct.getString("binding"),"clientKey" to client.getString("public"),"hostKey" to host.getString("public"))
            val pc=pairing("12345678","client"); val ph=pairing("12345678","host"); val cc=call("pairing.finish","handle" to pc.getLong("handle"),"data" to ph.getString("data")); val hc=call("pairing.finish","handle" to ph.getLong("handle"),"data" to pc.getString("data")); call("pairing.verify","handle" to cc.getLong("handle"),"data" to hc.getString("data")); call("pairing.verify","handle" to hc.getLong("handle"),"data" to cc.getString("data"))
            val bad=pairing("87654321","host"); val good=pairing("12345678","client"); val bc=call("pairing.finish","handle" to bad.getLong("handle"),"data" to good.getString("data")); val gc=call("pairing.finish","handle" to good.getLong("handle"),"data" to bad.getString("data")); try { call("pairing.verify","handle" to gc.getLong("handle"),"data" to bc.getString("data")); fail("Wrong code accepted") } catch(_:TetherException) { }
            try { NativeBridge.call(ByteArray(131073)); fail("Unbounded JNI input accepted") } catch(_:IllegalStateException) { }
        } finally { handles.forEach(NativeBridge::destroy) }
    }

    @Test fun keystoreTamperTruncationAndGenerationPredicates() {
        val context=InstrumentationRegistry.getInstrumentation().targetContext; val app="test.tether."+UUID.randomUUID().toString(); val digest=MessageDigest.getInstance("SHA-256").digest((context.packageName+"|"+app).toByteArray()).joinToString("") { "%02x".format(it) }; val folder=File(context.noBackupFilesDir,"tether-$digest"); val alias="tether.v1.$digest"; val handles=mutableListOf<Long>()
        try {
            val store=ProtectedStore(context,app); val identity=store.identity().also { handles.add(it.getLong("handle")) }; val reopened=ProtectedStore(context,app).identity().also { handles.add(it.getLong("handle")) }; assertTrue(bytes(identity,"public").contentEquals(bytes(reopened,"public")))
            val pending=PeerRecord(app,b64(ByteArray(32){7}),identity.getString("public"),TetherRoute.PrivateNetwork("127.0.0.1",7445),false); store.begin(pending); val confirmed=pending.copy(confirmed=true); store.replace(pending,confirmed)
            try { store.replace(pending,null); fail("Stale pending generation deleted confirmed trust") } catch(_:TetherException) { }
            val changed=confirmed.copy(route=TetherRoute.PrivateNetwork("127.0.0.1",7446),pairingId=UUID.randomUUID().toString()); store.replace(confirmed,changed)
            try { store.replace(confirmed,null); fail("Stale confirmed generation deleted new route") } catch(_:TetherException) { }; assertEquals(changed,store.records().single())
            val file=File(folder,"trust.bin"); val original=file.readBytes(); val tampered=original.copyOf().also { it[it.lastIndex]=(it.last().toInt() xor 1).toByte() }; file.writeBytes(tampered)
            try { store.records(); fail("Tampered ciphertext accepted") } catch(_:TetherException) { }; assertTrue(tampered.contentEquals(file.readBytes())); file.writeBytes(original)
            file.writeBytes(byteArrayOf(1,2,3)); try { store.identity(); fail("Truncated identity reset") } catch(_:TetherException) { }; assertTrue(file.readBytes().contentEquals(byteArrayOf(1,2,3))); file.writeBytes(original)
            val retained=store.identity().also { handles.add(it.getLong("handle")) }; assertTrue(bytes(retained,"public").contentEquals(bytes(identity,"public"))); store.replace(changed,null); assertTrue(store.records().isEmpty())
            val retainedCiphertext=file.readBytes(); val keyStore=KeyStore.getInstance("AndroidKeyStore").apply { load(null); deleteEntry(alias) }
            try { store.identity(); fail("Lost AES key silently regenerated the Noise identity") } catch(_:TetherException) { }; assertFalse(keyStore.containsAlias(alias)); assertTrue(retainedCiphertext.contentEquals(file.readBytes())); retainedCiphertext.fill(0); original.fill(0); tampered.fill(0)
        } finally { handles.forEach(NativeBridge::destroy); folder.deleteRecursively(); KeyStore.getInstance("AndroidKeyStore").apply { load(null); deleteEntry(alias) }; assertFalse(folder.exists()) }
    }

    @Test fun liveRustHostPairServicesMediaAndLeave()=runBlocking {
        val context=InstrumentationRegistry.getInstrumentation().targetContext; val file=File(context.filesDir,"tether-fixture.json"); assertTrue("A task-owned live host fixture must be installed",file.isFile); val fixture=JSONObject(file.readText()); val app=fixture.getString("appId"); val route=TetherRoute.PrivateNetwork("10.0.2.2",fixture.getInt("port")); val code=fixture.getString("code"); val client=TetherClient(context,app)
        try {
            val identity=NativeBridge.invoke("identity.generate"); try { Session.connect(route,app,identity.getLong("handle"),b64(ByteArray(32){9}),false); fail("Substituted host pin accepted") } catch(e:TetherException) { assertEquals("identity_mismatch",e.code) } finally { NativeBridge.destroy(identity.getLong("handle")) }
            val wrong=(if(code[0]=='0')"1" else "0")+code.drop(1)
            try { client.pair(route,wrong); fail("Wrong live pairing code accepted") } catch(_:TetherException) { }; assertTrue(client.records().isEmpty())
            val peer=client.pair(route,code); assertTrue(peer.confirmed); val status=client.status(peer); assertTrue(status.services.any { it.id=="tcp" && it.kind==ServiceKind.TCP }); assertTrue(status.services.any { it.id=="udp" && it.kind==ServiceKind.UDP })
            supervisorScope { val opening=async { client.openService(peer,"tcp",ServiceKind.TCP) }; yield(); client.closeStreams(peer.id)
                try { assertTrue("Retired service remained alive",opening.await().isClosed) } catch(e:TetherException) { assertEquals("closed",e.code) } }; assertTrue(client.status(peer).services.isNotEmpty())
            val payload=ByteArray(131072){(it%251).toByte()}; val tcp=client.openService(peer,"tcp",ServiceKind.TCP)
            try { coroutineScope { val sending=launch { for(offset in payload.indices step 16384)tcp.send(payload.copyOfRange(offset,minOf(offset+16384,payload.size))); tcp.finishSending() }; var count=0; val digest=MessageDigest.getInstance("SHA-256"); while(true) { val part=tcp.receive()?:break; digest.update(part); count+=part.size; assertTrue(count<=payload.size) }; sending.join(); assertEquals(payload.size,count); assertTrue(MessageDigest.getInstance("SHA-256").digest(payload).contentEquals(digest.digest())) } } finally { tcp.close() }
            val udp=client.openService(peer,"udp",ServiceKind.UDP); udp.send(ByteArray(0)); assertEquals(0,udp.receive()!!.size)
            val media=client.openMedia(peer,"udp"); try { media.send(byteArrayOf(1,2,3)); assertTrue(media.receive().contentEquals(byteArrayOf(1,2,3))); delay(6100); media.send(byteArrayOf(4)); assertTrue(media.receive().contentEquals(byteArrayOf(4))); assertTrue(media.statistics().packetsReceived>=2) } finally { media.close() }
            client.leave(peer); assertTrue(client.records().isEmpty()); var refused=false; try { withTimeout(3000) { udp.send(byteArrayOf(8)); udp.receive() } } catch(_:Exception) { refused=true } finally { udp.close() }; assertTrue("Host revocation must end the old service",refused)
            val results=JSONObject().put("pair",true).put("wrongCodeRefused",true).put("wrongPinRefused",true).put("tcpBytes",payload.size).put("udpEmpty",true).put("quicHeartbeatBeyondTTL",true).put("leave",true); File(context.filesDir,"tether-live-result.json").writeText(results.toString())
        } finally {
            client.close(); val digest=MessageDigest.getInstance("SHA-256").digest((context.packageName+"|"+app).toByteArray()).joinToString("") { "%02x".format(it) }; File(context.noBackupFilesDir,"tether-$digest").deleteRecursively(); KeyStore.getInstance("AndroidKeyStore").apply { load(null); deleteEntry("tether.v1.$digest") }
        }
    }
    @Test fun liveRustRelayBurstAndCancellation()=runBlocking {
        val context=InstrumentationRegistry.getInstrumentation().targetContext; val fixture=JSONObject(File(context.filesDir,"tether-fixture.json").readText()).getJSONObject("cloud"); val app=fixture.getString("appId"); val route=TetherRoute.Cloud("ws://127.0.0.1:${fixture.getInt("port")}/v1/relay",fixture.getString("hostId")); val client=TetherClient(context,app,true)
        try {
            val peer=client.pair(route,fixture.getString("code")); assertTrue(peer.confirmed); assertTrue(client.status(peer).services.any { it.id=="tcp" })
            val payload=ByteArray(524288){(it%239).toByte()}; val tcp=client.openService(peer,"tcp",ServiceKind.TCP)
            try { coroutineScope {
                val sending=launch { for(offset in payload.indices step 16384)tcp.send(payload.copyOfRange(offset,offset+16384)); tcp.finishSending() }
                delay(350); var count=0; val digest=MessageDigest.getInstance("SHA-256")
                while(true) { val part=tcp.receive()?:break; digest.update(part); count+=part.size; assertTrue(count<=payload.size) }
                sending.join(); assertEquals(payload.size,count); assertTrue(MessageDigest.getInstance("SHA-256").digest(payload).contentEquals(digest.digest()))
            } } finally { tcp.close() }
            val idle=client.openService(peer,"tcp",ServiceKind.TCP); val waiting=launch { idle.receive() }; delay(100); withTimeout(3000) { waiting.cancelAndJoin() }; assertTrue(idle.isClosed)
            val burst=client.openService(peer,"tcp",ServiceKind.TCP)
            try { repeat(24) { burst.send(ByteArray(16384){4}) }; delay(100) } finally { burst.close() }
            val udp=client.openService(peer,"udp",ServiceKind.UDP); try { udp.send(ByteArray(0)); assertEquals(0,udp.receive()!!.size) } finally { udp.close() }
            try { client.openMedia(peer,"udp"); fail("Cloud UDP must not silently use a private route") } catch(e:TetherException) { assertEquals("media_unavailable",e.code) }
            client.leave(peer); assertTrue(client.records().isEmpty())
            File(context.filesDir,"tether-cloud-result.json").writeText(JSONObject().put("pair",true).put("tcpBytes",payload.size).put("boundedBackpressure",true).put("idleReceiveCancelled",true).put("queuedReaderClosed",true).put("udpEmpty",true).put("leave",true).toString())
        } finally {
            client.close(); val digest=MessageDigest.getInstance("SHA-256").digest((context.packageName+"|"+app).toByteArray()).joinToString("") { "%02x".format(it) }; File(context.noBackupFilesDir,"tether-$digest").deleteRecursively(); KeyStore.getInstance("AndroidKeyStore").apply { load(null); deleteEntry("tether.v1.$digest") }
        }
    }

}
