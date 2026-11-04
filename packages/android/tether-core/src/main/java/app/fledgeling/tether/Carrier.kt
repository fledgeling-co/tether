package app.fledgeling.tether

import kotlinx.coroutines.*
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.selects.select
import okhttp3.*
import okio.ByteString.Companion.toByteString
import java.io.DataInputStream
import java.io.DataOutputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException
import org.json.JSONObject

private data class Completed<T>(val value:T)
internal suspend fun <T> withDeadline(milliseconds:Long,block:suspend()->T):T =
    (withTimeoutOrNull(milliseconds) { Completed(block()) } ?: throw TetherException("timeout")).value
internal interface Carrier { suspend fun send(bytes:ByteArray); suspend fun receive():ByteArray; fun close() }
internal class DirectCarrier private constructor(private val socket:Socket):Carrier {
    private val input=DataInputStream(socket.getInputStream()); private val output=DataOutputStream(socket.getOutputStream())
    override suspend fun send(bytes:ByteArray)=socketIo(socket) { requireTether(bytes.size<=65536,"invalid_frame"); output.writeInt(bytes.size); output.write(bytes); output.flush() }
    override suspend fun receive():ByteArray=socketIo(socket) { val count=input.readInt(); requireTether(count in 0..65536,"invalid_frame"); ByteArray(count).also(input::readFully) }
    override fun close() { runCatching { socket.close() } }
    companion object { suspend fun connect(route:TetherRoute.PrivateNetwork):Carrier {
        var owned:Socket?=null
        try { return withDeadline(15000) {
            val addresses=OwnedBlocking.run({ InetAddress.getAllByName(route.host).distinct().take(4) },{})
            requireTether(addresses.isNotEmpty()&&addresses.none { it.isAnyLocalAddress },"invalid_route")
            var result:Carrier?=null; var failure:Exception?=null
            for(address in addresses) { currentCoroutineContext().ensureActive(); val socket=Socket(); owned=socket
                try { socketIo(socket) { socket.soTimeout=0; socket.tcpNoDelay=true; socket.keepAlive=true; socket.connect(InetSocketAddress(address,route.port),15000) }; result=DirectCarrier(socket); break }
                catch(e:Exception) { socket.close(); if(e is CancellationException)throw e; failure=e }
            }
            result ?: throw failure ?: TetherException("connection_closed")
        } } catch(e:Exception) { owned?.close(); throw e }
    } }
}
internal class WebSocketCarrier private constructor(private val messages:Channel<ByteArray>):Carrier {
    lateinit var socket:WebSocket; private val closed=AtomicBoolean(); private val ended=CompletableDeferred<Unit>()
    override suspend fun send(bytes:ByteArray) { requireTether(bytes.size<=65536,"invalid_frame"); withDeadline(15000) {
        while(socket.queueSize()+bytes.size>65536) { requireTether(!closed.get(),"connection_closed"); delay(2) }
        currentCoroutineContext().ensureActive(); requireTether(!closed.get()&&socket.send(bytes.toByteString()),"connection_closed")
    } }
    override suspend fun receive():ByteArray=messages.receive()
    private fun end() { closed.set(true); ended.complete(Unit); messages.close(TetherException("connection_closed")) }
    override fun close() { end(); if(::socket.isInitialized)socket.cancel() }
    companion object {
        private val shared=OkHttpClient.Builder().connectTimeout(15,TimeUnit.SECONDS).readTimeout(0,TimeUnit.SECONDS).followRedirects(false).followSslRedirects(false).connectionPool(ConnectionPool(8,30,TimeUnit.SECONDS)).build()
        suspend fun connect(route:TetherRoute.Cloud,appId:String):Carrier {
            val messages=Channel<ByteArray>(8); val ready=CompletableDeferred<Unit>(); val result=WebSocketCarrier(messages)
            result.socket=shared.newWebSocket(Request.Builder().url(route.relayUrl).build(),object:WebSocketListener() {
                override fun onOpen(webSocket:WebSocket,response:Response) { if(!webSocket.send(JSONObject().put("type","client").put("app_id",appId).put("host_id",route.hostId).toString())) { ready.completeExceptionally(TetherException("connection_closed")); result.close() } }
                override fun onMessage(webSocket:WebSocket,text:String) { if(!ready.isCompleted) { try { requireTether(text.length<=2048&&JSONObject(text).getString("type")=="ready"); ready.complete(Unit) } catch(e:Exception) { ready.completeExceptionally(e); result.close() } } else result.close() }
                override fun onMessage(webSocket:WebSocket,bytes:okio.ByteString) {
                    if(!ready.isCompleted||bytes.size>65536) { result.close(); return }
                    // Blocking only this bounded WebSocket reader applies TCP backpressure instead of dropping ciphertext.
                    try { runBlocking { select<Unit> { messages.onSend(bytes.toByteArray()) {}; result.ended.onAwait { throw TetherException("connection_closed") } } } } catch(_:Exception) { result.close() }
                }
                override fun onFailure(webSocket:WebSocket,t:Throwable,response:Response?) { ready.completeExceptionally(TetherException("connection_closed")); result.end() }
                override fun onClosing(webSocket:WebSocket,code:Int,reason:String) { ready.completeExceptionally(TetherException("connection_closed")); result.end(); webSocket.close(code,null) }
                override fun onClosed(webSocket:WebSocket,code:Int,reason:String) { ready.completeExceptionally(TetherException("connection_closed")); result.end() }
            })
            try { withDeadline(15000) { ready.await() }; return result } catch(e:Exception) { result.close(); throw e }
        }
    }
}
private suspend fun <T> socketIo(socket:Socket,block:()->T):T=withContext(Dispatchers.IO) {
    suspendCancellableCoroutine { continuation ->
        continuation.invokeOnCancellation { runCatching { socket.close() } }
        try { val result=block(); if(continuation.isActive)continuation.resume(result) }
        catch(e:Exception) { if(continuation.isActive)continuation.resumeWithException(e) }
    }
}
