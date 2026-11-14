// XPCReply.swift
// Shared — add to both MailGPG and MailGPGExtension targets

import Foundation

/// Make one XPC call and await its reply, which is guaranteed to arrive: as the
/// reply block's result, or as the error that replaced it.
///
/// NSXPC delivers a call's failure (connection interrupted or invalidated, host
/// app quit or relaunched, unimplemented selector) to the proxy's error handler
/// INSTEAD of the reply block. A continuation only the reply block resumes then
/// never resumes, `decodedMessage` blocks on its semaphore, and Mail queues
/// every decode behind it. So the proxy is made per call, `makeProxy` installs
/// `onError` as part of its error handler, and both paths resume the same relay.
///
/// Lives in `Shared` so it can be tested against a real XPC connection; the
/// extension's own sources are not compiled into the test target.
nonisolated func withXPCReply<Proxy, T: Sendable>(
    proxy makeProxy: (_ onError: @escaping @Sendable (Error) -> Void) throws -> Proxy,
    _ send: (Proxy, OneShotRelay<T>) -> Void
) async throws -> T {
    try await withCheckedThrowingContinuation { continuation in
        let relay = OneShotRelay(continuation)
        do {
            send(try makeProxy { error in relay.resume(throwing: error) }, relay)
        } catch {
            relay.resume(throwing: error)
        }
    }
}

/// Thread-safe wrapper around a CheckedContinuation that guarantees exactly
/// one resume call even when two paths race (XPC reply vs. the proxy's error
/// handler).
nonisolated final class OneShotRelay<T: Sendable>: @unchecked Sendable {
    private let lock = NSLock()
    private var done = false
    private let continuation: CheckedContinuation<T, Error>

    init(_ continuation: CheckedContinuation<T, Error>) {
        self.continuation = continuation
    }

    func resume(returning value: T) {
        lock.lock(); defer { lock.unlock() }
        guard !done else { return }
        done = true
        continuation.resume(returning: value)
    }

    func resume(throwing error: Error) {
        lock.lock(); defer { lock.unlock() }
        guard !done else { return }
        done = true
        continuation.resume(throwing: error)
    }
}
