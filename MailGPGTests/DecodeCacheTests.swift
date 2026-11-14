// DecodeCacheTests.swift
// MailGPGTests

import XCTest
@testable import MailGPG

/// Holds async work until the test opens it: a decrypt waiting on gpg or on a
/// passphrase prompt.
private nonisolated final class Gate: @unchecked Sendable {
    private let lock = NSLock()
    private var isOpen = false
    private var waiters: [CheckedContinuation<Void, Never>] = []

    func wait() async {
        await withCheckedContinuation { continuation in
            lock.lock()
            if isOpen {
                lock.unlock()
                continuation.resume()
            } else {
                waiters.append(continuation)
                lock.unlock()
            }
        }
    }

    func open() {
        lock.lock()
        isOpen = true
        let pending = waiters
        waiters = []
        lock.unlock()
        pending.forEach { $0.resume() }
    }
}

/// Counts how often a decode actually ran.
private nonisolated final class Counter: @unchecked Sendable {
    private let lock = NSLock()
    private var count = 0
    var value: Int { lock.lock(); defer { lock.unlock() }; return count }
    func increment() { lock.lock(); count += 1; lock.unlock() }
}

private enum Outcome: Equatable {
    case value(String?)
    case timedOut
}

final class DecodeCacheTests: XCTestCase {

    private let key = "content-hash"

    /// Run a blocking `decode` off the main thread, as Mail calls it, and wait
    /// for its outcome without blocking the test forever.
    private func decodeInBackground(_ cache: DecodeCache<String>,
                                    work: @escaping @Sendable () async -> String?) -> (XCTestExpectation, () -> Outcome?) {
        let done = expectation(description: "decode returned")
        let lock = NSLock()
        nonisolated(unsafe) var outcome: Outcome?
        let key = key
        DispatchQueue.global().async {
            let result: Outcome
            do {
                result = .value(try cache.decode(key: key, work: work))
            } catch {
                result = .timedOut
            }
            lock.withLock { outcome = result }
            done.fulfill()
        }
        return (done, { lock.withLock { outcome } })
    }

    func testDecodeGivesUpWhenWorkNeverFinishes() {
        let cache = DecodeCache<String>(limit: 24, timeout: 0.1)
        let gate = Gate()
        defer { gate.open() }

        let (done, outcome) = decodeInBackground(cache) {
            await gate.wait()
            return "plaintext"
        }
        wait(for: [done], timeout: 2)
        XCTAssertEqual(outcome(), .timedOut)
        XCTAssertNil(cache.value(for: key), "nothing is cached on timeout")
    }

    func testLateResultIsStoredInCache() {
        let cache = DecodeCache<String>(limit: 24, timeout: 0.1)
        let gate = Gate()

        let (done, outcome) = decodeInBackground(cache) {
            await gate.wait()
            return "plaintext"
        }
        wait(for: [done], timeout: 2)
        XCTAssertEqual(outcome(), .timedOut)

        gate.open()
        let stored = expectation(for: NSPredicate { _, _ in cache.value(for: self.key) == "plaintext" },
                                 evaluatedWith: nil)
        wait(for: [stored], timeout: 2)
    }

    /// Mail asks again while the first decode still waits on gpg: the retry
    /// waits for that decode instead of starting another gpg and another
    /// passphrase prompt.
    func testConcurrentDecodesOfSameContentRunOnce() {
        let cache = DecodeCache<String>(limit: 24, timeout: 5)
        let gate = Gate()
        let runs = Counter()
        let work: @Sendable () async -> String? = {
            runs.increment()
            await gate.wait()
            return "plaintext"
        }

        let (first, firstOutcome) = decodeInBackground(cache, work: work)
        let (second, secondOutcome) = decodeInBackground(cache, work: work)
        Thread.sleep(forTimeInterval: 0.2)
        gate.open()
        wait(for: [first, second], timeout: 2)

        XCTAssertEqual(firstOutcome(), .value("plaintext"))
        XCTAssertEqual(secondOutcome(), .value("plaintext"))
        XCTAssertEqual(runs.value, 1)
    }

    func testFailedDecodeIsNotCached() {
        let cache = DecodeCache<String>(limit: 24, timeout: 5)
        let runs = Counter()
        let work: @Sendable () async -> String? = {
            runs.increment()
            return nil
        }

        let (first, firstOutcome) = decodeInBackground(cache, work: work)
        wait(for: [first], timeout: 2)
        let (second, secondOutcome) = decodeInBackground(cache, work: work)
        wait(for: [second], timeout: 2)

        XCTAssertEqual(firstOutcome(), .value(nil))
        XCTAssertEqual(secondOutcome(), .value(nil))
        XCTAssertEqual(runs.value, 2)
    }

    func testCacheHitSkipsWork() {
        let cache = DecodeCache<String>(limit: 24, timeout: 5)
        cache.store("plaintext", for: key)
        let (done, outcome) = decodeInBackground(cache) {
            XCTFail("work ran despite a cache hit")
            return nil
        }
        wait(for: [done], timeout: 2)
        XCTAssertEqual(outcome(), .value("plaintext"))
    }

    func testOldestEntryEvictedBeyondLimit() {
        let cache = DecodeCache<String>(limit: 2, timeout: 5)
        cache.store("a", for: "1")
        cache.store("b", for: "2")
        cache.store("c", for: "3")
        XCTAssertNil(cache.value(for: "1"))
        XCTAssertEqual(cache.value(for: "2"), "b")
        XCTAssertEqual(cache.value(for: "3"), "c")
    }
}
