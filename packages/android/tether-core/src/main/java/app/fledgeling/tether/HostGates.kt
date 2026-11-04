package app.fledgeling.tether

import kotlinx.coroutines.sync.Mutex

/** Counts users before obtaining a mutex, so pruning cannot create two gates for one host. */
internal class HostGates {
    private data class Gate(val mutex:Mutex=Mutex(),var users:Int=0)
    private val monitor=Any(); private val gates=mutableMapOf<String,Gate>()
    internal val size:Int get()=synchronized(monitor) { gates.size }
    suspend fun <T> run(id:String,block:suspend()->T):T {
        val gate=synchronized(monitor) { gates.getOrPut(id) { Gate() }.also { it.users++ } }; val acquired=gate.mutex.tryLock()
        try { if(!acquired)throw TetherException("busy"); return block() }
        finally { if(acquired)gate.mutex.unlock(); synchronized(monitor) { gate.users--; if(gate.users==0)gates.remove(id) } }
    }
}
