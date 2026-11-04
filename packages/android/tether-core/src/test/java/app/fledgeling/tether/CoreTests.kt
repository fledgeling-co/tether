package app.fledgeling.tether

import kotlinx.coroutines.*
import org.json.JSONObject
import kotlinx.coroutines.flow.first
import java.util.concurrent.CountDownLatch
import java.util.concurrent.atomic.AtomicInteger
import java.util.Base64
import kotlin.test.*

class CoreTests {
    private fun peer()=PeerRecord("app.tether.test",b64(ByteArray(32){1}),b64(ByteArray(32){2}),TetherRoute.PrivateNetwork("127.0.0.1",7445),true)
    @Test fun invalidRoutesNeverReachNetwork() {
        listOf(TetherRoute.PrivateNetwork("0.0.0.0",1),TetherRoute.PrivateNetwork("foo/bar",1),TetherRoute.PrivateNetwork("host",0),TetherRoute.Cloud("ws://public.example/v1/relay","a".repeat(52)),TetherRoute.Cloud("wss://user:secret@relay.example/v1/relay","a".repeat(52)),TetherRoute.Cloud("wss://relay.example/v1/relay?key=secret","a".repeat(52))).forEach { assertFailsWith<TetherException> { it.validate() } }
        TetherRoute.PrivateNetwork("::1",7445).validate(); TetherRoute.Cloud("wss://relay.example/v1/relay","a".repeat(52)).validate()
    }
    @Test fun invitationIsScopedBoundedAndExpires() {
        val now=1_800_000_000_000L
        val j=JSONObject().put("version",1).put("appID","app.tether.test").put("code","12345678").put("expiresAt",(now+60000)/1000.0-978307200).put("route",JSONObject().put("privateNetwork",JSONObject().put("host","mac.local").put("port",7445)))
        fun uri()="tether://pair?data="+Base64.getUrlEncoder().withoutPadding().encodeToString(j.toString().toByteArray())
        val invite=TetherPairingInvitation.decode(uri(),"app.tether.test",now); assertEquals(TetherRoute.PrivateNetwork("mac.local",7445),invite.route); assertFalse(invite.toString().contains("12345678"))
        assertFailsWith<TetherException> { TetherPairingInvitation.decode(uri(),"other.app",now) }; assertFailsWith<TetherException> { TetherPairingInvitation.decode(uri(),"app.tether.test",now+60001) }; assertFailsWith<TetherException> { TetherPairingInvitation.decode(uri()+"&extra=1","app.tether.test",now) }
        j.put("expiresAt",(now+302000)/1000.0-978307200); assertFailsWith<TetherException> { TetherPairingInvitation.decode(uri(),"app.tether.test",now) }
    }
    @Test fun stalePeerAndMalformedKeyRefused() { peer().validate("app.tether.test"); assertFailsWith<TetherException> { peer().copy(hostKey="malformed").validate("app.tether.test") }; assertFailsWith<TetherException> { peer().validate("different.app") } }
    @Test fun disconnectSupersedesLateReconnect()=runBlocking {
        val fake=Fake(peer()); val store=TetherConnectionStore(fake); store.load(); val connecting=launch { runCatching { store.reconnect(fake.peer.id) } }; fake.started.await(); store.disconnect(fake.peer.id); fake.reply.complete(HostStatus(emptyList())); connecting.join(); assertEquals(ConnectionState.Offline,store.hosts.value.single().state); assertEquals(1,fake.statusCalls); assertTrue(fake.closedStreams>0); store.close()
    }
    @Test fun reloadRetiresChangedRecordsAndLateServices()=runBlocking {
        val fake=Fake(peer()); val store=TetherConnectionStore(fake); store.load(); fake.reply.complete(HostStatus(listOf(HostService("api",ServiceKind.TCP)))); store.reconnect(fake.peer.id)
        val opening=launch { runCatching { store.openService(fake.peer.id,"api",ServiceKind.TCP) } }; fake.openStarted.await(); store.disconnect(fake.peer.id); fake.openReply.complete(Unit); opening.join(); assertTrue(fake.channelClosed)
        val replacement=fake.peer.copy(route=TetherRoute.PrivateNetwork("changed.local",7445),pairingId=java.util.UUID.randomUUID().toString()); fake.peer=replacement; store.load(); assertEquals(replacement,store.hosts.value.single().record); assertEquals(ConnectionState.Offline,store.hosts.value.single().state); store.close()
    }
    @Test fun ownedNativeResultIsDisposedAfterCancellation()=runBlocking {
        val started=CompletableDeferred<Unit>(); val gate=CountDownLatch(1); val disposed=CompletableDeferred<Int>(); val count=AtomicInteger()
        val request=launch { runCatching { OwnedBlocking.run({ started.complete(Unit); gate.await(); 7 },{ count.incrementAndGet(); disposed.complete(it) }) } }
        started.await(); request.cancel(); gate.countDown(); request.join(); assertEquals(7,withTimeout(2000) { disposed.await() }); assertEquals(1,count.get())
    }
    @Test fun explicitOwnerCloseDisposesLateNativeResult()=runBlocking {
        val started=CompletableDeferred<Unit>(); val gate=CountDownLatch(1); val registered=CompletableDeferred<java.io.Closeable>(); val disposed=CompletableDeferred<Int>()
        val request=async { runCatching { OwnedBlocking.run({ started.complete(Unit); gate.await(); 9 },{ disposed.complete(it) },{ registered.complete(it) }) } }
        started.await(); registered.await().close(); gate.countDown(); assertEquals("closed",(request.await().exceptionOrNull() as TetherException).code); assertEquals(9,withTimeout(2000) { disposed.await() })
    }
    @Test fun busyIoPreservesHealthyStreamAndFinOrder()=runBlocking {
        val started=CompletableDeferred<Unit>(); val finish=CompletableDeferred<Unit>(); val writes=mutableListOf<Int>(); var releases=0
        val stream=TetherServiceStream(ServiceKind.TCP,object:SecureChannel { override suspend fun send(data:ByteArray) { started.complete(Unit); finish.await(); writes.add(data.size) }; override suspend fun receive()=ByteArray(0); override fun close(){} }) { releases++ }
        val first=launch { stream.send(byteArrayOf(1)) }; started.await()
        assertEquals("busy",assertFailsWith<TetherException> { stream.send(byteArrayOf(2)) }.code); assertEquals("busy",assertFailsWith<TetherException> { stream.finishSending() }.code); assertFalse(stream.isClosed)
        finish.complete(Unit); first.join(); stream.finishSending(); assertEquals(listOf(1,0),writes); assertEquals(null,stream.receive()); assertTrue(stream.isClosed); assertEquals(1,releases)
    }
    @Test fun confirmedPairDoesNotFailWhenHostIsRevokedAfterAck()=runBlocking {
        val fake=Fake(peer()); fake.statusFailure=TetherException("peer_revoked"); val store=TetherConnectionStore(fake)
        assertEquals(fake.peer,store.pair(fake.peer.route,"12345678")); withTimeout(2000) { store.hosts.first { it.singleOrNull()?.state==ConnectionState.Revoked } }; store.close()
    }
    @Test fun idleHostGatesArePrunedWithoutSplittingAnActiveGate()=runBlocking {
        val gates=HostGates(); repeat(1024) { gates.run("host-$it"){} }; assertEquals(0,gates.size)
        val started=CompletableDeferred<Unit>(); val finish=CompletableDeferred<Unit>(); val active=launch { gates.run("same") { started.complete(Unit); finish.await() } }; started.await()
        assertEquals("busy",assertFailsWith<TetherException> { gates.run("same"){} }.code); assertEquals(1,gates.size); finish.complete(Unit); active.join(); assertEquals(0,gates.size)
    }
    @Test fun ownTimeoutIsAnErrorAndParentCancellationStaysCancellation()=runBlocking {
        assertEquals("timeout",assertFailsWith<TetherException> { withDeadline(10) { awaitCancellation() } }.code)
        val started=CompletableDeferred<Unit>(); val request=launch { withDeadline(10000) { started.complete(Unit); awaitCancellation() } }; started.await(); request.cancelAndJoin(); assertTrue(request.isCancelled)
    }
    @Test fun cancellationAtOwnedResultDispatchDisposesUndeliveredValue()=runBlocking {
        val queued=java.util.concurrent.ConcurrentLinkedQueue<Runnable>(); val dispatcher=object:CoroutineDispatcher() { override fun dispatch(context:kotlin.coroutines.CoroutineContext,block:Runnable) { queued.add(block) } }; val ready=CompletableDeferred<Unit>(); val disposed=AtomicInteger(); var delivered=false
        val job=launch(dispatcher) { OwnedBlocking.run({ 7 },{ disposed.incrementAndGet() },unregister={ ready.complete(Unit) }); delivered=true }
        queued.remove().run(); withTimeout(2000) { ready.await() }; job.cancel(); while(true) { val next=queued.poll()?:break; next.run() }; job.join(); assertFalse(delivered); assertEquals(1,disposed.get())
    }
    @Test fun cancelledReceiveClosesAndReleasesOnce()=runBlocking {
        val started=CompletableDeferred<Unit>(); var closes=0; var releases=0
        val stream=TetherServiceStream(ServiceKind.TCP,object:SecureChannel { override suspend fun send(data:ByteArray){}; override suspend fun receive():ByteArray { started.complete(Unit); awaitCancellation() }; override fun close(){ closes++ } }) { releases++ }
        val waiting=launch { stream.receive() }; started.await(); waiting.cancelAndJoin(); stream.close(); assertTrue(stream.isClosed); assertEquals(1,closes); assertEquals(1,releases)
    }
    private class Fake(var peer:PeerRecord):TetherClientManaging {
        override val appId="app.tether.test"; val started=CompletableDeferred<Unit>(); val reply=CompletableDeferred<HostStatus>(); val openStarted=CompletableDeferred<Unit>(); val openReply=CompletableDeferred<Unit>(); var statusCalls=0; var closedStreams=0; var channelClosed=false; var statusFailure:TetherException?=null
        override suspend fun records()=listOf(peer)
        override suspend fun status(peer:PeerRecord):HostStatus { statusCalls++; started.complete(Unit); statusFailure?.let { throw it }; return withContext(NonCancellable) { reply.await() } }
        override suspend fun openService(peer:PeerRecord,name:String,kind:ServiceKind):TetherServiceStream { openStarted.complete(Unit); kotlin.coroutines.suspendCoroutine<Unit> { continuation -> openReply.invokeOnCompletion { continuation.resumeWith(Result.success(Unit)) } }; return TetherServiceStream(kind,object:SecureChannel { override suspend fun send(data:ByteArray){}; override suspend fun receive()=ByteArray(0); override fun close(){channelClosed=true} }){} }
        override fun closeStreams(hostId:String) { closedStreams++ }
        override fun close(){}
        override suspend fun pair(route:TetherRoute,code:String):PeerRecord=peer
        override suspend fun recover(peer:PeerRecord):PeerRecord=error("unused")
        override suspend fun discardPending(peer:PeerRecord)=error("unused")
        override suspend fun updateRoute(peer:PeerRecord,route:TetherRoute):PeerRecord=error("unused")
        override suspend fun leave(peer:PeerRecord)=error("unused")
        override suspend fun forgetLocally(peer:PeerRecord)=error("unused")
        override suspend fun openMedia(peer:PeerRecord,name:String):TetherMediaSession=error("unused")
    }
}
