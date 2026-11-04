package app.fledgeling.tether

import kotlinx.coroutines.suspendCancellableCoroutine
import java.io.Closeable
import java.util.concurrent.FutureTask
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.coroutines.resumeWithException

/** Cancellation never drops an owned native result between an IO worker and its caller. */
internal object OwnedBlocking {
    private val executor=ThreadPoolExecutor(4,4,30,TimeUnit.SECONDS,LinkedBlockingQueue(16)) { job -> Thread(job,"tether-owned-io").apply { isDaemon=true } }.apply { allowCoreThreadTimeOut(true) }
    suspend fun <T> run(loader:()->T,dispose:(T)->Unit,register:(Closeable)->Unit={},unregister:(Closeable)->Unit={}):T = suspendCancellableCoroutine { continuation ->
        val finished=AtomicBoolean(); lateinit var task:FutureTask<Unit>
        lateinit var operation:Closeable
        operation=Closeable { if(finished.compareAndSet(false,true))continuation.resumeWithException(TetherException("closed")); task.cancel(false); executor.remove(task); unregister(operation) }
        task=FutureTask {
            try { val result=loader(); if(finished.compareAndSet(false,true))continuation.resume(result) { _,value,_ -> dispose(value) } else dispose(result) }
            catch(e:Exception) { if(finished.compareAndSet(false,true))continuation.resumeWithException(e) }
            finally { unregister(operation) }
        }
        continuation.invokeOnCancellation { finished.set(true); task.cancel(false); executor.remove(task); unregister(operation) }
        register(operation)
        if(!finished.get())try { executor.execute(task) } catch(_:java.util.concurrent.RejectedExecutionException) { if(finished.compareAndSet(false,true))continuation.resumeWithException(TetherException("busy")); unregister(operation) } else unregister(operation)
    }
}
