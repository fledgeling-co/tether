#if os(macOS)
    import Darwin
    import Foundation

    private func terminateOwnedProcess(_ process: Process) {
        guard process.isRunning else { return }
        process.terminate()
        DispatchQueue.global(qos: .userInitiated).asyncAfter(deadline: .now() + 1) {
            if process.isRunning {
                _ = Darwin.kill(process.processIdentifier, SIGKILL)
            }
        }
    }

    private final class CommandCancellation: @unchecked Sendable {
        private let lock = NSLock()
        private var process: Process?
        private var cancelled = false
        func launch(_ process: Process) throws {
            try lock.withLock {
                guard !cancelled else { throw CancellationError() }
                self.process = process; try process.run()
            }
        }

        func cancel() {
            lock.withLock {
                cancelled = true
                if let process {
                    terminateOwnedProcess(process)
                }
            }
        }
    }

    actor ProcessHostHelper: HostHelper {
        private let executable: URL
        private let writer = DispatchQueue(label: "tether.owner-pipe.writer", qos: .userInitiated)
        private var process: Process?
        private var input: Pipe?
        private var stopping: Task<Bool, Never>?
        private var reader: Task<Void, Never>?
        private var events: AsyncThrowingStream<HostEvent, Error>.Continuation?
        private var buffer = Data()
        private var generation = UUID()
        private struct Pending {
            let continuation: CheckedContinuation<Data, Error>
            let timeout: Task<Void, Never>
        }

        private var pending: [String: Pending] = [:]
        init(executable: URL) {
            self.executable = executable
        }

        deinit {
            let input = input, process = process
            writer.async { try? input?.fileHandleForWriting.close() }
            reader?.cancel()
            DispatchQueue.global(qos: .userInitiated).asyncAfter(deadline: .now() + 2) {
                if let process {
                    terminateOwnedProcess(process)
                }
            }
        }

        func execute(_ arguments: [String]) async throws -> Data {
            try Task.checkCancellation()
            let executable = executable, cancellation = CommandCancellation()
            return try await withTetherDeadline(seconds: 20) {
                try await withTaskCancellationHandler {
                    try await withCheckedThrowingContinuation { continuation in
                        // Process pipes can block. Keep their reads on a blocking GCD worker,
                        // outside both this actor and Swift's cooperative executor.
                        DispatchQueue.global(qos: .userInitiated).async {
                            do {
                                let process = Process(); process.executableURL = executable; process.arguments = arguments
                                let output = Pipe(); process.standardOutput = output; process.standardError = FileHandle.nullDevice
                                process.standardInput = FileHandle.nullDevice
                                try cancellation.launch(process)
                                var result = Data()
                                while let chunk = try output.fileHandleForReading.read(upToCount: 4096), !chunk.isEmpty {
                                    guard result.count + chunk.count <= 262_144 else {
                                        terminateOwnedProcess(process); throw TetherHostControllerError.invalidStatus
                                    }
                                    result.append(chunk)
                                }
                                process.waitUntilExit()
                                guard process.terminationStatus == 0 else { throw TetherHostControllerError.helperFailed }
                                continuation.resume(returning: result)
                            } catch { continuation.resume(throwing: error) }
                        }
                    }
                } onCancel: { cancellation.cancel() }
            }
        }

        func start(_ arguments: [String]) async throws -> AsyncThrowingStream<HostEvent, Error> {
            try Task.checkCancellation()
            guard process == nil, stopping == nil else { throw TetherHostControllerError.alreadyRunning }
            let child = Process(); child.executableURL = executable; child.arguments = arguments
            let stdin = Pipe(), stdout = Pipe()
            child.standardInput = stdin; child.standardOutput = stdout; child.standardError = FileHandle.nullDevice
            let token = UUID(); generation = token
            let (stream, continuation) = AsyncThrowingStream<HostEvent, Error>.makeStream(bufferingPolicy: .bufferingNewest(16))
            child.terminationHandler = { [weak self] _ in Task { await self?.finished(token) } }
            try child.run()
            process = child; input = stdin; events = continuation
            continuation.onTermination = { [weak self] _ in Task { _ = await self?.stop(ifGeneration: token) } }
            reader = Task.detached { [weak self] in
                while !Task.isCancelled {
                    let chunk = stdout.fileHandleForReading.availableData
                    guard !chunk.isEmpty else { return }
                    await self?.received(chunk, token: token)
                }
            }
            if Task.isCancelled {
                _ = await stop(ifGeneration: token); throw CancellationError()
            }
            return stream
        }

        func request(command: String, expectedApp: String, clientID: String?) async throws -> Data {
            try Task.checkCancellation()
            guard ["pair-code", "pairing-status", "clients", "revoke", "inspect"].contains(command),
                  stopping == nil, process?.isRunning == true, let input, pending.count < 8
            else {
                throw TetherHostControllerError.helperFailed
            }
            let id = UUID().uuidString, token = generation
            var request: [String: Any] = ["v": 1, "request_id": id, "command": command, "expected_app": expectedApp]
            if let clientID {
                request["client_id"] = clientID
            }
            var bytes = try JSONSerialization.data(withJSONObject: request); bytes.append(10)
            guard bytes.count <= 2048 else { throw TetherHostControllerError.invalidProfile }
            let output = bytes
            return try await withTaskCancellationHandler {
                try await withCheckedThrowingContinuation { continuation in
                    guard !Task.isCancelled else { continuation.resume(throwing: CancellationError()); return }
                    let timer = Task { [weak self] in
                        do { try await Task.sleep(for: .seconds(15)) } catch { return }
                        await self?.requestTimedOut(id, token: token)
                    }
                    pending[id] = Pending(continuation: continuation, timeout: timer)
                    writer.async { [weak self] in
                        do { try input.fileHandleForWriting.write(contentsOf: output) }
                        catch { Task { await self?.cancelRequest(id, error: TetherHostControllerError.helperFailed) } }
                    }
                }
            } onCancel: { Task { await self.cancelRequest(id, error: CancellationError()) } }
        }

        private func requestTimedOut(_ id: String, token: UUID) async {
            guard pending[id] != nil, generation == token else { return }
            cancelRequest(id, error: TetherClientError.timeout)
            events?.finish(throwing: TetherClientError.timeout)
            _ = await stop(ifGeneration: token)
        }

        private func cancelRequest(_ id: String, error: any Error) {
            guard let request = pending.removeValue(forKey: id) else { return }
            request.timeout.cancel(); request.continuation.resume(throwing: error)
        }

        func stop() async -> Bool {
            await stop(ifGeneration: generation)
        }

        private func stop(ifGeneration token: UUID) async -> Bool {
            if let stopping {
                return await stopping.value
            }
            guard token == generation else { return true }
            generation = UUID()
            let child = process, input = input, writer = writer
            buffer.removeAll(); reader?.cancel(); reader = nil
            events?.finish(); events = nil
            for id in Array(pending.keys) {
                cancelRequest(id, error: TetherHostControllerError.helperFailed)
            }
            let stopping = Task<Bool, Never> {
                writer.async { try? input?.fileHandleForWriting.close() }
                guard let child else { return true }
                if await Self.exited(child, within: .seconds(2)) {
                    return true
                }
                terminateOwnedProcess(child)
                return await Self.exited(child, within: .seconds(3))
            }
            self.stopping = stopping
            let exited = await stopping.value
            if exited {
                process = nil; self.input = nil
            }
            self.stopping = nil
            return exited
        }

        private static func exited(_ child: Process, within interval: Duration) async -> Bool {
            let deadline = ContinuousClock.now.advanced(by: interval)
            while child.isRunning, ContinuousClock.now < deadline {
                try? await Task.sleep(for: .milliseconds(20))
            }
            return !child.isRunning
        }

        private func received(_ chunk: Data, token: UUID) async {
            guard token == generation else { return }
            buffer.append(chunk)
            guard buffer.count <= 524_288 else { await failed(token); return }
            while let newline = buffer.firstIndex(of: 10) {
                let line = Data(buffer[..<newline]); buffer.removeSubrange(...newline)
                do {
                    guard !line.isEmpty, line.count <= 262_144,
                          let json = try JSONSerialization.jsonObject(with: line) as? [String: Any]
                    else {
                        throw TetherHostControllerError.invalidStatus
                    }
                    if json["event"] as? String == "reply" {
                        guard let id = json["request_id"] as? String, let request = pending.removeValue(forKey: id) else {
                            continue // Late replies to canceled requests carry no new authority.
                        }
                        request.timeout.cancel()
                        if json["ok"] as? Bool == true, let payload = json["payload"] {
                            do { try request.continuation.resume(returning: JSONSerialization.data(withJSONObject: payload, options: [.fragmentsAllowed])) }
                            catch { request.continuation.resume(throwing: TetherHostControllerError.invalidStatus) }
                        } else {
                            request.continuation.resume(throwing: TetherHostControllerError.helperFailed)
                        }
                    } else {
                        try events?.yield(JSONDecoder().decode(HostEvent.self, from: line))
                    }
                } catch { await failed(token); return }
            }
        }

        private func finished(_ token: UUID) async {
            guard token == generation else { return }
            events?.finish(throwing: TetherHostControllerError.helperFailed)
            _ = await stop(ifGeneration: token)
        }

        private func failed(_ token: UUID) async {
            guard token == generation else { return }
            events?.finish(throwing: TetherHostControllerError.invalidStatus)
            _ = await stop(ifGeneration: token)
        }
    }
#endif
