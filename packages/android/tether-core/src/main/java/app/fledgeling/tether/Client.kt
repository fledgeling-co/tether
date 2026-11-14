package app.fledgeling.tether

import android.content.Context
import kotlinx.coroutines.*
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import org.json.JSONObject
import java.io.Closeable
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger

internal interface SecureChannel : Closeable { suspend fun send(data:ByteArray); suspend fun receive():ByteArray }
interface TetherClientManaging : Closeable {
    val appId:String
    suspend fun records():List<PeerRecord>
    suspend fun pair(route:TetherRoute,code:String):PeerRecord
    suspend fun status(peer:PeerRecord):HostStatus
    suspend fun recover(peer:PeerRecord):PeerRecord
    suspend fun discardPending(peer:PeerRecord)
    suspend fun updateRoute(peer:PeerRecord,route:TetherRoute):PeerRecord
    suspend fun leave(peer:PeerRecord)
    suspend fun forgetLocally(peer:PeerRecord)
    suspend fun openService(peer:PeerRecord,name:String,kind:ServiceKind):TetherServiceStream
    suspend fun openMedia(peer:PeerRecord,name:String):TetherMediaSession
    fun closeStreams(hostId:String)
    fun retireStreams(hostId:String):Closeable { closeStreams(hostId); return Closeable {} }
    /** Pairs by comparing a six-digit code shown on both devices. [decision] returns this device owner's answer, or null while undecided. */
    /** [onStoring] fires once both have approved and the acknowledgement is about to make the pairing irreversible. */
    suspend fun pairNearby(route:TetherRoute,deviceName:String,deviceKind:String,onCode:suspend(String)->Unit,onHostApproved:suspend()->Unit,decision:()->Boolean?,onStoring:suspend()->Unit={},inviteToken:String?=null):NearbyOutcome = throw TetherException("nearby_closed")
}

internal class Session private constructor(private val carrier:Carrier, private val cipher:Long, val hostKey:String, val binding:String,private val release:()->Unit):SecureChannel {
    private val send=Mutex(); private val receive=Mutex(); private val closed=AtomicBoolean(false)
    override suspend fun send(data:ByteArray) { if(!send.tryLock()) throw TetherException("busy"); try { requireTether(!closed.get(),"closed"); currentCoroutineContext().ensureActive(); val encrypted=bytes(NativeBridge.invoke("transport.encrypt","handle" to cipher,"data" to b64(data))); try { carrier.send(encrypted) } finally { encrypted.fill(0) }; currentCoroutineContext().ensureActive() } catch(e:Exception) { close(); throw e } finally { send.unlock() } }
    override suspend fun receive():ByteArray { if(!receive.tryLock()) throw TetherException("busy"); try { requireTether(!closed.get(),"closed"); val encrypted=carrier.receive(); return try { bytes(NativeBridge.invoke("transport.decrypt","handle" to cipher,"data" to b64(encrypted))).also { currentCoroutineContext().ensureActive() } } finally { encrypted.fill(0) } } catch(e:Exception) { close(); throw e } finally { receive.unlock() } }
    suspend fun control(type:String,vararg fields:Pair<String,Any>) { val j=JSONObject().put("v",1).put("type",type); fields.forEach { (k,v)->j.put(k,v) }; val data=j.toString().toByteArray(); try { requireTether(data.size<=4096); send(data) } finally { data.fill(0) } }
    suspend fun controlReply(expected:String):JSONObject = withDeadline(15000) { val data=receive(); try { requireTether(data.size<=4096); val j=JSONObject(String(data,Charsets.UTF_8)); requireTether(j.getInt("v")==1); if(j.getString("type")=="error") throw TetherException(j.optString("code","invalid_protocol")); requireTether(j.getString("type")==expected); j } finally { data.fill(0) } }
    /** Sends a record a shared flow produced; it already carries `v`. */
    suspend fun sendRecord(record:JSONObject) { val data=record.toString().toByteArray(); try { requireTether(data.size<=4096,"invalid_frame"); send(data) } finally { data.fill(0) } }
    /** One control record for a shared flow to judge, host errors included. */
    suspend fun record():JSONObject = withDeadline(15000) { val data=receive(); try { requireTether(data.size<=4096); JSONObject(String(data,Charsets.UTF_8)) } finally { data.fill(0) } }
    override fun close() { if(closed.compareAndSet(false,true)) { carrier.close(); NativeBridge.destroy(cipher); release() } }
    companion object { suspend fun connect(route:TetherRoute,appId:String,identity:Long,pin:String?,allowLoopback:Boolean,data:Boolean=false):Session {
        route.validate(allowLoopback); val quota=if(data)dataSlots else controlSlots; requireTether(quota.tryAcquire(),"service_capacity"); val released=AtomicBoolean(); val release={ if(released.compareAndSet(false,true))quota.release(); Unit }; var owned:Carrier?=null
        try { val carrier=when(route) { is TetherRoute.PrivateNetwork -> DirectCarrier.connect(route); is TetherRoute.Cloud -> WebSocketCarrier.connect(route,appId) }; owned=carrier; var handshake=0L; var cipher=0L
        try {
            handshake=NativeBridge.invoke("noise.new","identity" to identity,"app" to appId,"role" to "client").getLong("handle")
            carrier.send(bytes(NativeBridge.invoke("noise.write","handle" to handshake,"data" to "")))
            val incoming=withDeadline(15000) { carrier.receive() }; val metadata=try { NativeBridge.invoke("noise.read","handle" to handshake,"data" to b64(incoming)) } finally { incoming.fill(0) }
            val remote=b64(bytes(metadata,"remoteStatic",32)); requireTether(pin==null||pin==remote,"identity_mismatch")
            carrier.send(bytes(NativeBridge.invoke("noise.write","handle" to handshake,"data" to "")))
            val finished=NativeBridge.invoke("noise.finish","handle" to handshake); handshake=0; cipher=finished.getLong("handle"); requireTether(finished.getBoolean("finished")); val binding=b64(bytes(finished,"binding",32)); return Session(carrier,cipher,remote,binding,release)
        } catch(e:Exception) { carrier.close(); NativeBridge.destroy(cipher); throw e } finally { NativeBridge.destroy(handshake) }
        } catch(e:Exception) { owned?.close(); release(); throw e }
    }
        private val controlSlots=kotlinx.coroutines.sync.Semaphore(8)
        private val dataSlots=kotlinx.coroutines.sync.Semaphore(16)
    }
}

/** A bounded, full-duplex encrypted fixed host service. Close explicitly when the app stops using it. */
class TetherServiceStream internal constructor(val kind:ServiceKind,private val session:SecureChannel,private val release:()->Unit):Closeable {
    private val closed=AtomicBoolean(false); private val sendAdmission=Mutex(); private val receiveAdmission=Mutex(); @Volatile private var sendingFinished=false; @Volatile private var receivingFinished=false
    val isClosed:Boolean get()=closed.get()
    suspend fun send(data:ByteArray) { requireTether(data.size<=16384,"invalid_frame"); if(!sendAdmission.tryLock())throw TetherException("busy")
        try { requireTether(!closed.get()&&!sendingFinished,"closed"); if(kind==ServiceKind.TCP&&data.isEmpty())return; session.send(data) }
        catch(e:TetherException) { if(e.code!="busy")close(); throw e } catch(e:Exception) { close(); throw e } finally { sendAdmission.unlock() }
    }
    suspend fun receive():ByteArray? { if(!receiveAdmission.tryLock())throw TetherException("busy")
        try { requireTether(!closed.get(),"closed"); if(receivingFinished)return null; val data=session.receive(); if(kind==ServiceKind.TCP&&data.isEmpty()) { receivingFinished=true; if(sendingFinished)close(); return null }; return data }
        catch(e:TetherException) { if(e.code!="busy")close(); throw e } catch(e:Exception) { close(); throw e } finally { receiveAdmission.unlock() }
    }
    suspend fun finishSending() { if(!sendAdmission.tryLock())throw TetherException("busy")
        try { requireTether(kind==ServiceKind.TCP&&!closed.get()&&!sendingFinished,"closed"); session.send(ByteArray(0)); sendingFinished=true; if(receivingFinished)close() }
        catch(e:TetherException) { if(e.code!="busy")close(); throw e } catch(e:Exception) { close(); throw e } finally { sendAdmission.unlock() }
    }
    override fun close() { if(closed.compareAndSet(false,true)) { session.close(); release() } }
}

/** One app-scoped client identity, with an encrypted no-backup Android Keystore record store. */
class TetherClient(context:Context,override val appId:String,private val allowInsecureLoopbackForTesting:Boolean=false):TetherClientManaging {
    private val store=ProtectedStore(context.applicationContext,appId,allowInsecureLoopbackForTesting)
    private val closed=AtomicBoolean(); private val life=Any(); private val pairing=Mutex(); private val identityMutex=Mutex()
    @Volatile private var identity=0L
    private var identityPublic=""
    private val identityLoads=ConcurrentHashMap.newKeySet<Closeable>()
    private val streamCount=AtomicInteger(); private val streams=mutableMapOf<java.util.UUID,Pair<String,Closeable>>()
    private val sessions=ConcurrentHashMap.newKeySet<Session>(); private val epochs=mutableMapOf<String,Long>()
    private data class Pending(val host:String?,val data:Boolean,val job:Deferred<*>)
    private val pending=mutableMapOf<java.util.UUID,Pending>(); private val mutations=HostGates()
    init { scope(appId) }
    private fun ensureOpen() { requireTether(!closed.get(),"closed") }
    private suspend fun identity():Pair<Long,String> = identityMutex.withLock {
        ensureOpen()
        if(identity==0L) {
            val j=OwnedBlocking.run({ store.identity() }, { NativeBridge.destroy(it.getLong("handle")) }, { identityLoads.add(it); if(closed.get())it.close() }, { identityLoads.remove(it) })
            val owned=j.getLong("handle")
            try { val public=b64(bytes(j,"public",32)); synchronized(life) { ensureOpen(); identity=owned; identityPublic=public } }
            catch(e:Exception) { NativeBridge.destroy(owned); throw e }
        }
        identity to identityPublic
    }
    override suspend fun records():List<PeerRecord> { ensureOpen(); return withContext(Dispatchers.IO) { store.records() } }
    private suspend fun <T> operation(host:String?,data:Boolean=false,token:java.util.UUID=java.util.UUID.randomUUID(),block:suspend(Long)->T):T=supervisorScope {
        var ticket=0L; var delivered=false
        val job=async(Dispatchers.IO,start=CoroutineStart.LAZY) { block(ticket) }
        try {
            synchronized(life) { ensureOpen(); ticket=host?.let { epochs[it] }?:0L; pending[token]=Pending(host,data,job) }
            job.start(); val value=job.await(); currentCoroutineContext().ensureActive(); delivered=true; value
        } catch(e:CancellationException) { currentCoroutineContext().ensureActive(); throw TetherException("closed") }
        finally {
            val orphan=synchronized(life) { pending.remove(token); val orphan=if(!delivered)streams.remove(token)?.second else null; prune(host); orphan }
            if(!delivered)job.cancel(); orphan?.close()
        }
    }
    private suspend fun <T> mutate(peer:PeerRecord,block:suspend()->T):T = mutations.run(peer.id) { operation(peer.id) { block() } }
    private fun prune(host:String?) { if(host!=null&&pending.values.none { it.host==host }&&streams.values.none { it.first==host })epochs.remove(host) }
    private suspend fun connect(peer:PeerRecord,route:TetherRoute=peer.route,data:Boolean=false):Session {
        peer.validate(appId,allowInsecureLoopbackForTesting); ensureOpen(); requireTether(withContext(Dispatchers.IO) { store.matches(peer) },"identity_mismatch")
        val(id,pub)=identity(); requireTether(pub==peer.clientKey,"identity_mismatch")
        val session=Session.connect(route,appId,id,peer.hostKey,allowInsecureLoopbackForTesting,data)
        try { synchronized(life) { ensureOpen(); sessions.add(session) }; return session } catch(e:Exception) { session.close(); throw e }
    }
    private fun closeSession(session:Session) { sessions.remove(session); session.close() }
    override suspend fun pair(route:TetherRoute,code:String):PeerRecord {
        ensureOpen(); if(!pairing.tryLock())throw TetherException("busy")
        try { return operation(null) {
            var session:Session?=null
            try {
                val(id,pub)=identity(); val active=Session.connect(route,appId,id,null,allowInsecureLoopbackForTesting); session=active
                synchronized(life) { ensureOpen(); sessions.add(active) }
                val begun=NativeBridge.invoke("code.begin","app" to appId,"code" to code,"binding" to active.binding,"clientKey" to pub,"hostKey" to active.hostKey)
                when(val outcome=drive(active,route,pub,begun)) { is NearbyOutcome.Paired->outcome.record; else->throw TetherException("invalid_protocol") }
            } finally { session?.let(::closeSession) }
        } } finally { pairing.unlock() }
    }
    override suspend fun pairNearby(route:TetherRoute,deviceName:String,deviceKind:String,onCode:suspend(String)->Unit,onHostApproved:suspend()->Unit,decision:()->Boolean?,onStoring:suspend()->Unit,inviteToken:String?):NearbyOutcome {
        ensureOpen(); requireTether(route is TetherRoute.PrivateNetwork,"nearby_closed"); if(!pairing.tryLock())throw TetherException("busy")
        try { return operation(null) {
            var session:Session?=null
            try {
                val(id,pub)=identity(); val active=Session.connect(route,appId,id,null,allowInsecureLoopbackForTesting); session=active
                synchronized(life) { ensureOpen(); sessions.add(active) }
                // The shared flow applies the approval rules: an answer counts only after the code has been up for a second and
                // the decision has read undecided since it appeared; a decline is final and beats a racing ready.
                val fields=mutableListOf("app" to appId,"binding" to active.binding,"clientKey" to pub,"hostKey" to active.hostKey,"name" to deviceName,"kind" to deviceKind)
                if(inviteToken!=null)fields.add("inviteToken" to inviteToken)
                val begun=NativeBridge.invoke("nearby.begin",*fields.toTypedArray())
                drive(active,route,pub,begun,onCode,onHostApproved,decision,onStoring)
            } finally { session?.let(::closeSession) }
        } } finally { pairing.unlock() }
    }
    /** Performs a shared Rust pairing flow's actions until it ends; trust is saved only when it says so. */
    private suspend fun drive(active:Session,route:TetherRoute,pub:String,begun:JSONObject,onCode:suspend(String)->Unit={},onHostApproved:suspend()->Unit={},decision:()->Boolean?={ null },onStoring:suspend()->Unit={}):NearbyOutcome {
        val flow=begun.optLong("handle"); val started=System.nanoTime(); fun now()=(System.nanoTime()-started)/1_000_000
        fun current():Any=decision()?:JSONObject.NULL
        var pending:PeerRecord?=null; var confirmed:PeerRecord?=null
        try {
            var actions=begun.getJSONArray("actions")
            while(true) {
                var next:org.json.JSONArray?=null
                for(i in 0 until actions.length()) { val action=actions.getJSONObject(i); currentCoroutineContext().ensureActive()
                    when(action.getString("do")) {
                        "send"->active.sendRecord(action.getJSONObject("message"))
                        "receive"->{ val message=active.record(); next=NativeBridge.invoke("flow.receive","handle" to flow,"message" to message,"decision" to current(),"now" to now()).getJSONArray("actions") }
                        "wait"->{ delay(action.optLong("ms",600)); next=NativeBridge.invoke("flow.tick","handle" to flow,"decision" to current(),"now" to now()).getJSONArray("actions") }
                        // Only once the code is on screen does its read time start.
                        "show_code"->{ onCode(action.getString("code").also { requireTether(it.matches(Regex("[0-9]{6}"))) }); next=NativeBridge.invoke("flow.shown","handle" to flow,"decision" to current(),"now" to now()).getJSONArray("actions") }
                        "host_approved"->onHostApproved()
                        // The durable pending record precedes ack; an interrupted completion is recoverable.
                        // From here the ack makes completion irreversible, so the UI stops offering Cancel; a decline until then still wins.
                        "store_pending"->{ val record=PeerRecord(appId,active.hostKey,pub,route,false); withContext(Dispatchers.IO) { store.begin(record) }; pending=record; onStoring(); next=NativeBridge.invoke("flow.stored","handle" to flow,"decision" to current()).getJSONArray("actions") }
                        "discard_pending"->{ pending?.let { record -> withContext(Dispatchers.IO) { store.replace(record,null) } }; pending=null }
                        "confirm"->{ val record=pending?:throw TetherException("pairing_pending"); val done=record.copy(confirmed=true); withContext(Dispatchers.IO) { store.replace(record,done) }; confirmed=done }
                        "outcome"->return when(action.getString("outcome")) { "paired"->NearbyOutcome.Paired(confirmed?:throw TetherException("pairing_pending")); "declined"->NearbyOutcome.Declined; "expired"->NearbyOutcome.Expired; else->throw TetherException("invalid_protocol") }
                        "failed"->throw TetherException(action.optString("code","invalid_protocol").take(64))
                        else->throw TetherException("invalid_protocol")
                    }
                }
                actions=next?:throw TetherException("invalid_protocol")
            }
        } finally { NativeBridge.destroy(flow) }
    }
    private fun decodeStatus(j:JSONObject):HostStatus { val values=j.getJSONArray("services"); requireTether(values.length()<=32); val services=(0 until values.length()).map { val v=values.getJSONObject(it); val id=v.getString("id"); scope(id); val kind=when(v.getString("kind")) { "tcp"->ServiceKind.TCP; "udp"->ServiceKind.UDP; else->throw TetherException("invalid_protocol") }; HostService(id,kind) }; requireTether(services.map { it.id }.distinct().size==services.size); return HostStatus(services) }
    override suspend fun status(peer:PeerRecord):HostStatus { requireTether(peer.confirmed,"pairing_pending"); return operation(peer.id) { val session=connect(peer); try { session.control("host.status"); decodeStatus(session.controlReply("host.status")) } finally { closeSession(session) } } }
    override suspend fun recover(peer:PeerRecord):PeerRecord=mutate(peer) { val session=connect(peer); try { session.control("pair.status"); session.controlReply("pair.done"); if(peer.confirmed)peer else peer.copy(confirmed=true).also { confirmed -> withContext(Dispatchers.IO) { store.replace(peer,confirmed) } } } finally { closeSession(session) } }
    override suspend fun discardPending(peer:PeerRecord)=mutate(peer) { requireTether(!peer.confirmed,"pairing_exists"); withContext(Dispatchers.IO) { store.replace(peer,null); retireStreams(peer.id).close() } }
    override suspend fun updateRoute(peer:PeerRecord,route:TetherRoute):PeerRecord=mutate(peer) {
        requireTether(peer.confirmed,"pairing_pending"); val session=connect(peer,route)
        try { session.control("host.status"); decodeStatus(session.controlReply("host.status")); currentCoroutineContext().ensureActive(); val replacement=peer.copy(route=route,pairingId=java.util.UUID.randomUUID().toString()); withContext(Dispatchers.IO) { store.replace(peer,replacement); retireStreams(peer.id).close() }; replacement }
        finally { closeSession(session) }
    }
    override suspend fun leave(peer:PeerRecord)=mutate(peer) { requireTether(peer.confirmed,"pairing_pending"); val session=connect(peer)
        try { session.control("peer.leave"); session.controlReply("peer.left"); withContext(Dispatchers.IO) { store.replace(peer,null); retireStreams(peer.id).close() } } finally { closeSession(session) }
    }
    override suspend fun forgetLocally(peer:PeerRecord)=mutate(peer) { requireTether(peer.confirmed,"pairing_pending"); withContext(Dispatchers.IO) { store.replace(peer,null); retireStreams(peer.id).close() } }
    private fun reserve(host:String):Pair<java.util.UUID,()->Unit> {
        if(streamCount.incrementAndGet()>8) { streamCount.decrementAndGet(); throw TetherException("stream_limit") }
        val token=java.util.UUID.randomUUID(); val released=AtomicBoolean()
        return token to { if(released.compareAndSet(false,true)) { synchronized(life) { streams.remove(token); prune(host) }; streamCount.decrementAndGet() }; Unit }
    }
    private fun publish(token:java.util.UUID,host:String,ticket:Long,resource:Closeable) = synchronized(life) {
        ensureOpen(); requireTether((epochs[host]?:0L)==ticket,"closed"); requireTether(pending[token]?.job?.isActive==true,"closed")
        requireTether(when(resource) { is TetherServiceStream->!resource.isClosed; is TetherMediaSession->!resource.isClosed; else->false },"closed"); streams[token]=host to resource
    }
    override suspend fun openService(peer:PeerRecord,name:String,kind:ServiceKind):TetherServiceStream {
        scope(name); requireTether(peer.confirmed,"pairing_pending"); val(token,release)=reserve(peer.id)
        try { return operation(peer.id,true,token) { ticket ->
            var session:Session?=null; var stream:TetherServiceStream?=null
            try { val active=connect(peer,data=true); session=active; active.control("service.open","service" to name); val reply=active.controlReply("service.ready"); requireTether(reply.getString("kind")==kind.name.lowercase(),"service_denied")
                val result=TetherServiceStream(kind,active) { sessions.remove(active); release() }; stream=result
                requireTether(withContext(Dispatchers.IO) { store.matches(peer) },"identity_mismatch"); currentCoroutineContext().ensureActive(); publish(token,peer.id,ticket,result); result
            } catch(e:Exception) { stream?.close(); session?.let(::closeSession); release(); throw e }
        } } catch(e:Exception) { release(); throw e }
    }
    override suspend fun openMedia(peer:PeerRecord,name:String):TetherMediaSession {
        scope(name); requireTether(peer.confirmed&&peer.route is TetherRoute.PrivateNetwork,"media_unavailable"); val(token,release)=reserve(peer.id)
        try { return operation(peer.id,true,token) { ticket ->
            var session:Session?=null; var media:TetherMediaSession?=null
            try { val active=connect(peer,data=true); session=active; active.control("media.open","service" to name); val offer=active.controlReply("media.ready")
                val result=TetherMediaSession.open((peer.route as TetherRoute.PrivateNetwork).host,offer,active) { sessions.remove(active); release() }; media=result
                requireTether(withContext(Dispatchers.IO) { store.matches(peer) },"identity_mismatch"); currentCoroutineContext().ensureActive(); publish(token,peer.id,ticket,result); result
            } catch(e:Exception) { media?.close(); session?.let(::closeSession); release(); throw e }
        } } catch(e:Exception) { release(); throw e }
    }
    /** Detach atomically; closing the returned batch cannot touch a later host generation. */
    override fun retireStreams(hostId:String):Closeable {
        val jobs:List<Deferred<*>>; val resources:List<Closeable>
        synchronized(life) {
            epochs[hostId]=(epochs[hostId]?:0)+1
            val ids=pending.filterValues { it.host==hostId&&it.data }.keys.toList(); jobs=ids.mapNotNull { pending.remove(it)?.job }
            val streamIds=streams.filterValues { it.first==hostId }.keys.toList(); resources=streamIds.mapNotNull { streams.remove(it)?.second }; prune(hostId)
        }
        return Closeable { jobs.forEach { it.cancel() }; resources.forEach(Closeable::close) }
    }
    override fun closeStreams(hostId:String) { retireStreams(hostId).close() }
    override fun close() {
        if(!closed.compareAndSet(false,true))return
        val jobs:List<Deferred<*>>; val resources:List<Closeable>
        synchronized(life) { jobs=pending.values.map { it.job }; pending.clear(); resources=streams.values.map { it.second }; streams.clear(); epochs.clear() }
        jobs.forEach { it.cancel() }; identityLoads.toList().forEach(Closeable::close); resources.forEach(Closeable::close); sessions.toList().forEach(Session::close); sessions.clear(); NativeBridge.destroy(identity); identity=0
    }
}
