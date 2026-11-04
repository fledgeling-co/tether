package app.fledgeling.tether

import kotlinx.coroutines.*
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import org.json.JSONObject
import java.io.Closeable
import java.util.concurrent.atomic.AtomicBoolean

data class MediaStatistics(val roundTripMilliseconds:Double,val bytesSent:Long,val bytesReceived:Long,val packetsSent:Long,val packetsReceived:Long,val dropped:Long)
/** Native pinned QUIC packets. Apps own codecs and packetization; cloud does not silently fall back. */
class TetherMediaSession private constructor(private val handle:Long,val maximumDatagramSize:Int,private val session:Session,private val scope:CoroutineScope,private val release:()->Unit):Closeable {
    private val closed=AtomicBoolean(); private val sending=Mutex(); private val receiving=Mutex()
    val isClosed:Boolean get()=closed.get()
    suspend fun send(packet:ByteArray) { requireTether(!closed.get(),"closed"); requireTether(packet.size<=maximumDatagramSize,"invalid_frame"); if(!sending.tryLock())throw TetherException("busy")
        try { currentCoroutineContext().ensureActive(); val result=NativeBridge.invoke("media.send","handle" to handle,"data" to b64(packet)); currentCoroutineContext().ensureActive(); requireTether(result.getBoolean("accepted")); requireTether(!closed.get(),"closed") }
        catch(e:TetherException) { if(e.code!="media_backpressure")close(); throw e } catch(e:Exception) { close(); throw e } finally { sending.unlock() }
    }
    suspend fun receive():ByteArray { requireTether(!closed.get(),"closed"); if(!receiving.tryLock())throw TetherException("busy")
        try { return run { while(true) { currentCoroutineContext().ensureActive(); val result=receiveSlots.withPermit { withContext(Dispatchers.IO) { suspendCancellableCoroutine<JSONObject> { continuation -> continuation.invokeOnCancellation { close() }; try { val value=NativeBridge.invoke("media.receive_wait","handle" to handle,"timeout_ms" to 100); if(continuation.isActive)continuation.resumeWith(Result.success(value)) } catch(e:Exception) { if(continuation.isActive)continuation.resumeWith(Result.failure(e)) } } } }; currentCoroutineContext().ensureActive(); requireTether(!closed.get(),"closed"); when(result.getString("state")) { "pending"->Unit; "data"->return@run bytes(result); else->throw TetherException("connection_closed") } }; @Suppress("UNREACHABLE_CODE") throw TetherException("closed") } }
        catch(e:Exception) { close(); throw e } finally { receiving.unlock() }
    }
    fun statistics():MediaStatistics { requireTether(!closed.get(),"closed"); val j=NativeBridge.invoke("media.stats","handle" to handle); val rtt=j.getDouble("rtt_ms"); requireTether(rtt.isFinite()&&rtt>=0); return MediaStatistics(rtt,j.getLong("bytes_sent"),j.getLong("bytes_received"),j.getLong("packets_sent"),j.getLong("packets_received"),j.getLong("dropped")) }
    override fun close() { if(closed.compareAndSet(false,true)) { runCatching { NativeBridge.invoke("media.close","handle" to handle) }; session.close(); scope.cancel(); release() } }
    internal companion object { private val receiveSlots=Semaphore(8)
    suspend fun open(address:String,offer:JSONObject,control:Session,release:()->Unit):TetherMediaSession {
        val lease=b64(bytes(offer,"lease_id",16)); val token=b64(bytes(offer,"token",32)); val pin=b64(bytes(offer,"cert_pin",32)); val maximum=offer.getInt("max_datagram"); val port=offer.getInt("port")
        requireTether(maximum in 1..1200 && port in 1..65535 && offer.getInt("heartbeat_seconds")==2 && offer.getInt("lease_ttl_seconds")==5)
        val handle=NativeBridge.invoke("media.client.start","address" to address,"port" to port,"lease_id" to lease,"token" to token,"cert_pin" to pin).getLong("handle")
        val scope=CoroutineScope(SupervisorJob()+Dispatchers.IO); val failed=AtomicBoolean(); val media=java.util.concurrent.atomic.AtomicReference<TetherMediaSession?>(null)
        scope.launch { try { var next=android.os.SystemClock.elapsedRealtime()+2000; while(isActive) { delay(maxOf(0,next-android.os.SystemClock.elapsedRealtime())); withDeadline(2000) { control.control("media.heartbeat","lease_id" to lease); control.controlReply("media.alive") }; next+=2000 } } catch(e:Exception) { if(isActive) { failed.set(true); media.get()?.close(); control.close() } } }
        try { val negotiated=withDeadline(15000) { var found=0; while(found==0) { currentCoroutineContext().ensureActive(); requireTether(!failed.get(),"connection_closed"); val poll=NativeBridge.invoke("media.poll","handle" to handle); when(poll.getString("state")) { "connecting"->delay(10); "ready"->{ val n=poll.getInt("max_datagram"); requireTether(n in 1..1200); found=minOf(n,maximum) }; else->throw TetherException("connection_closed") } }; found }
            val result=TetherMediaSession(handle,negotiated,control,scope,release); media.set(result); requireTether(!failed.get(),"connection_closed"); currentCoroutineContext().ensureActive(); return result
        } catch(e:Exception) { runCatching { NativeBridge.invoke("media.close","handle" to handle) }; control.close(); scope.cancel(); release(); throw e }
    } }
}
