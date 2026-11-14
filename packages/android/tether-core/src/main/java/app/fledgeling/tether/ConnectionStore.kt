package app.fledgeling.tether

import kotlinx.coroutines.*
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.io.Closeable
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

/** UI-neutral multi-host state. Selection never changes another host's open services. */
class TetherConnectionStore(private val client:TetherClientManaging):Closeable {
    val appId:String get()=client.appId
    private val mutableHosts=MutableStateFlow<List<ManagedHost>>(emptyList()); val hosts:StateFlow<List<ManagedHost>> = mutableHosts.asStateFlow()
    private val mutableSelected=MutableStateFlow<String?>(null); val selectedHostId:StateFlow<String?> = mutableSelected.asStateFlow()
    private val state=Any(); private val reload=Mutex(); private val scope=CoroutineScope(SupervisorJob()+Dispatchers.IO)
    private val operations=HostGates(); private val monitors=mutableMapOf<String,Job>(); private val connecting=mutableMapOf<String,Job>(); private val openings=mutableMapOf<UUID,Pair<String,Job>>()
    private val opened=mutableMapOf<UUID,Pair<String,Closeable>>(); private val generations=mutableMapOf<String,Long>(); private var generation=0L; private var closed=false
    private fun ensureOpen() { requireTether(!closed,"closed") }
    private fun current(id:String):ManagedHost=synchronized(state) { ensureOpen(); mutableHosts.value.singleOrNull { it.id==id } ?: throw TetherException("identity_mismatch") }
    fun selectHost(id:String?)=synchronized(state) { ensureOpen(); requireTether(id==null||mutableHosts.value.any { it.id==id },"identity_mismatch"); mutableSelected.value=id }
    suspend fun load() = reload.withLock {
        synchronized(state) { ensureOpen() }; val records=client.records(); val retired=mutableListOf<Closeable>(); val jobs=mutableListOf<Job>()
        synchronized(state) {
            ensureOpen(); val old=mutableHosts.value.associateBy { it.id }; val fresh=records.associateBy { it.id }
            old.values.filter { fresh[it.id]!=it.record }.forEach { host -> retired.add(client.retireStreams(host.id)); generations[host.id]=++generation; opened.filterValues { it.first==host.id }.keys.toList().forEach(opened::remove); monitors.remove(host.id)?.let(jobs::add); connecting.remove(host.id)?.let(jobs::add); openings.filterValues { it.first==host.id }.keys.toList().forEach { openings.remove(it)?.second?.let(jobs::add) } }
            mutableHosts.value=records.map { r->old[r.id]?.takeIf { it.record==r } ?: ManagedHost(r,if(r.confirmed)ConnectionState.Offline else ConnectionState.Pending) }
            if(mutableSelected.value==null||records.none { it.id==mutableSelected.value })mutableSelected.value=records.firstOrNull()?.id; generations.keys.retainAll(fresh.keys)
        }
        val self=currentCoroutineContext()[Job]; jobs.filter { it!==self }.forEach { it.cancel() }; retired.forEach(Closeable::close)
    }
    private suspend fun <T> exclusive(id:String,block:suspend()->T):T=operations.run(id,block)
    suspend fun pair(route:TetherRoute,code:String):PeerRecord { try { val peer=client.pair(route,code); load(); selectHost(peer.id); scope.launch { runCatching { reconnect(peer.id) } }; return peer } catch(e:Exception) { withContext(NonCancellable) { runCatching { load() } }; throw e } }
    /** Pairs with a nearby computer by comparing a code, then selects and connects it. */
    suspend fun pairNearby(route:TetherRoute,deviceName:String,deviceKind:String,onCode:suspend(String)->Unit,onHostApproved:suspend()->Unit,decision:()->Boolean?,onStoring:suspend()->Unit={},inviteToken:String?=null):NearbyOutcome {
        try { val outcome=client.pairNearby(route,deviceName,deviceKind,onCode,onHostApproved,decision,onStoring,inviteToken)
            if(outcome is NearbyOutcome.Paired) { load(); selectHost(outcome.record.id); scope.launch { runCatching { reconnect(outcome.record.id) } } }
            return outcome
        } catch(e:Exception) { withContext(NonCancellable) { runCatching { load() } }; throw e }
    }
    private fun valid(id:String,ticket:Long,peer:PeerRecord):Boolean = !closed && generations[id]==ticket && mutableHosts.value.any { it.id==id && it.record==peer }
    private fun publish(id:String,ticket:Long,peer:PeerRecord,newState:ConnectionState,services:List<HostService> = emptyList()):Boolean = synchronized(state) {
        if(!valid(id,ticket,peer))false else { mutableHosts.value=mutableHosts.value.map { if(it.id==id)it.copy(state=newState,services=services,notice=notice(newState)) else it }; true }
    }
    private fun fail(id:String,ticket:Long,peer:PeerRecord,error:Exception) {
        val detached=synchronized(state) { if(valid(id,ticket,peer)) { publish(id,ticket,peer,map(error)); client.retireStreams(id) } else null }
        detached?.close()
    }
    private suspend fun statusWithRetry(peer:PeerRecord):HostStatus { var failure:Exception?=null; for(wait in listOf(0L,1000L,2000L,4000L)) { if(wait>0)delay(wait); try { return client.status(peer) } catch(e:Exception) { if(e is CancellationException)throw e; if((e as? TetherException)?.code in listOf("peer_revoked","identity_mismatch","pairing_pending"))throw e; failure=e } }; throw failure?:TetherException("connection_closed") }
    suspend fun reconnect(id:String)=exclusive(id) {
        val peer=current(id).record; requireTether(peer.confirmed,"pairing_pending"); val self=currentCoroutineContext()[Job]?:throw TetherException("closed"); val old:Job?; val ticket:Long
        synchronized(state) { ensureOpen(); old=monitors.remove(id); ticket=++generation; generations[id]=ticket; connecting[id]=self }; old?.cancel(); publish(id,ticket,peer,ConnectionState.Connecting)
        try {
            val status=statusWithRetry(peer); currentCoroutineContext().ensureActive()
            var monitor:Job?=null
            synchronized(state) {
                if(valid(id,ticket,peer)) {
                    publish(id,ticket,peer,ConnectionState.Connected,status.services)
                    monitor=scope.launch(start=CoroutineStart.LAZY) {
                        while(isActive) { delay(15000); try { val next=statusWithRetry(peer); if(!publish(id,ticket,peer,ConnectionState.Connected,next.services))return@launch }
                            catch(e:Exception) { if(e is CancellationException)throw e; fail(id,ticket,peer,e); return@launch } }
                    }; monitors[id]=monitor!!
                }
            }
            requireTether(monitor!=null,"closed"); monitor?.start()
        } catch(e:Exception) { fail(id,ticket,peer,e); throw e }
        finally { synchronized(state) { if(connecting[id]===self)connecting.remove(id) } }
    }
    suspend fun disconnect(id:String) {
        val jobs=mutableListOf<Job>(); val detached:Closeable; synchronized(state) { ensureOpen(); detached=client.retireStreams(id); generations[id]=++generation; opened.filterValues { it.first==id }.keys.toList().forEach(opened::remove); monitors.remove(id)?.let(jobs::add); connecting.remove(id)?.let(jobs::add); openings.filterValues { it.first==id }.keys.toList().forEach { openings.remove(it)?.second?.let(jobs::add) }; mutableHosts.value=mutableHosts.value.map { if(it.id==id)it.copy(state=if(it.record.confirmed)ConnectionState.Offline else ConnectionState.Pending,services=emptyList(),notice=null) else it } }
        val self=currentCoroutineContext()[Job]; jobs.filter { it!==self }.forEach { it.cancel() }; detached.close()
    }
    suspend fun changeRoute(id:String,route:TetherRoute)=exclusive(id) { val peer=current(id).record; client.updateRoute(peer,route); disconnect(id); load() }
    suspend fun leave(id:String)=exclusive(id) { val peer=current(id).record; client.leave(peer); disconnect(id); load() }
    suspend fun forgetLocally(id:String)=exclusive(id) { val peer=current(id).record; client.forgetLocally(peer); disconnect(id); load() }
    suspend fun recover(id:String)=exclusive(id) { client.recover(current(id).record); load() }
    suspend fun discardPending(id:String)=exclusive(id) { client.discardPending(current(id).record); disconnect(id); load() }
    private suspend fun <T:Closeable> open(id:String,create:suspend(PeerRecord)->T):T {
        val host:ManagedHost; val ticket:Long; val token=UUID.randomUUID(); val self=currentCoroutineContext()[Job]?:throw TetherException("closed")
        synchronized(state) { host=current(id); requireTether(host.state==ConnectionState.Connected,"connection_closed"); ticket=generations[id]?:throw TetherException("closed"); opened.filterValues { when(val resource=it.second) { is TetherServiceStream->resource.isClosed; is TetherMediaSession->resource.isClosed; else->true } }.keys.toList().forEach(opened::remove); requireTether(openings.values.count { it.first==id }+opened.values.count { it.first==id }<6,"stream_limit"); openings[token]=id to self }
        var result:T?=null
        try { val value=create(host.record); result=value; currentCoroutineContext().ensureActive(); synchronized(state) { requireTether(valid(id,ticket,host.record)&&current(id).state==ConnectionState.Connected,"closed"); opened[token]=id to value }; return value }
        catch(e:Exception) { result?.close(); throw e } finally { synchronized(state) { openings.remove(token) } }
    }
    suspend fun openService(id:String,name:String,kind:ServiceKind):TetherServiceStream=open(id) { client.openService(it,name,kind) }
    suspend fun openMedia(id:String,name:String):TetherMediaSession=open(id) { client.openMedia(it,name) }
    override fun close() { val jobs=synchronized(state) { if(closed)return; closed=true; generations.clear(); mutableHosts.value=mutableHosts.value.map { it.copy(state=ConnectionState.Offline,services=emptyList()) }; (monitors.values+connecting.values+openings.values.map { it.second }).toList().also { monitors.clear(); connecting.clear(); openings.clear(); opened.clear() } }; jobs.forEach { it.cancel() }; scope.cancel(); client.close() }
    private fun map(e:Exception):ConnectionState = when((e as? TetherException)?.code) { "peer_revoked"->ConnectionState.Revoked; "identity_mismatch"->ConnectionState.IdentityMismatch; "service_capacity","stream_limit"->ConnectionState.Capacity; "pairing_pending"->ConnectionState.Pending; else->ConnectionState.Offline }
    private fun notice(s:ConnectionState):String?=when(s) { ConnectionState.Offline->"The host has not answered. Its saved identity is retained."; ConnectionState.Revoked->"This device's permission was removed at the host."; ConnectionState.IdentityMismatch->"The host identity changed. Saved trust was retained."; ConnectionState.Capacity->"The host is busy. Try reconnecting later."; else->null }
}
