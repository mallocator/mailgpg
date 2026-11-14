// DecodeCache.swift
// Shared — add to both MailGPG and MailGPGExtension targets

import Foundation

/// The extension's decode results, keyed by message content, plus the decodes
/// still running.
///
/// MailKit's `decodedMessage` is synchronous and Mail serializes decode
/// requests to the extension, so one call that never returns makes every
/// message spin, PGP or not. `decode` therefore waits a bounded time. The work
/// keeps running after a timeout: when it finishes, its result is still
/// stored, so the next look at the message is a cache hit, and a call for the
/// same content while it runs waits on it instead of starting another gpg and
/// another passphrase prompt.
///
/// Lives in `Shared` so it can be tested; the extension's own sources are not
/// compiled into the test target.
nonisolated final class DecodeCache<Value>: @unchecked Sendable {

    struct TimedOut: Error {}

    /// One running decode, which any number of callers may wait on.
    private final class Pending: @unchecked Sendable {
        private let finished = DispatchGroup()
        private let lock = NSLock()
        private var result: Value?

        init() { finished.enter() }

        func finish(_ value: Value?) {
            lock.withLock { result = value }
            finished.leave()
        }

        /// The result, or `TimedOut` if the decode is still running at the deadline.
        func wait(timeout: TimeInterval) throws -> Value? {
            guard finished.wait(timeout: .now() + timeout) == .success else { throw TimedOut() }
            return lock.withLock { result }
        }
    }

    private let limit: Int
    private let timeout: TimeInterval
    /// Guards the three below.
    private let lock = NSLock()
    /// Entries hold decrypted plaintext, so the cache is bounded: unbounded
    /// growth would keep every message you ever opened in memory, in the clear,
    /// until Mail quit.
    private var entries: [String: Value] = [:]
    /// Keys of `entries`, oldest first.
    private var order: [String] = []
    private var running: [String: Pending] = [:]

    init(limit: Int, timeout: TimeInterval) {
        self.limit = limit
        self.timeout = timeout
    }

    func value(for key: String) -> Value? {
        lock.withLock { entries[key] }
    }

    func store(_ value: Value, for key: String) {
        lock.withLock { insert(value, for: key) }
    }

    func removeAll() {
        lock.withLock {
            entries.removeAll()
            order.removeAll()
        }
    }

    /// The cached result for `key`, or the result of `work`, run at most once
    /// at a time per key. A nil result is returned but not cached, so a failed
    /// decode is tried again next time.
    ///
    /// Throws `TimedOut` when the decode outlasts the timeout. Nothing is cached
    /// then; the work's eventual result is.
    func decode(key: String, work: @escaping @Sendable () async -> Value?) throws -> Value? {
        let pending: Pending
        lock.lock()
        if let hit = entries[key] {
            lock.unlock()
            return hit
        }
        if let inFlight = running[key] {
            pending = inFlight
            lock.unlock()
        } else {
            pending = Pending()
            running[key] = pending
            lock.unlock()
            // Detached: the caller blocks this thread, so the work must not
            // need it. At the caller's priority, so the wait is no priority
            // inversion.
            Task.detached(priority: Task.currentPriority) {
                let value = await work()
                // Cache and in-flight table change together, so a new caller
                // finds the result in one or the other.
                self.lock.withLock {
                    if let value { self.insert(value, for: key) }
                    self.running[key] = nil
                }
                pending.finish(value)
            }
        }
        return try pending.wait(timeout: timeout)
    }

    /// Caller holds `lock`.
    private func insert(_ value: Value, for key: String) {
        if entries[key] == nil {
            order.append(key)
            while order.count > limit {
                entries.removeValue(forKey: order.removeFirst())
            }
        }
        entries[key] = value
    }
}
