// GPGAgent.swift
// MailGPG (host app only)

import Foundation

/// Manages the gpg-agent lifecycle and pinentry configuration.
///
/// gpg-agent is the long-running daemon that:
///  - caches passphrases so the user isn't prompted on every operation
///  - communicates with smartcard daemons (scdaemon) for YubiKey / OpenPGP card
///  - delegates PIN / passphrase prompts to a `pinentry` program
///
/// On macOS, `pinentry-mac` is the native GUI pinentry. Without it, GPG falls
/// back to `pinentry-curses` which needs a terminal — and silently hangs in a
/// background app like ours.
struct GPGAgent {

    // MARK: - Tool path helper

    /// Returns the path to a GPG-suite companion binary (e.g. `gpgconf`)
    /// by replacing the `gpg` filename in the located GPG binary's directory.
    static func toolPath(_ name: String) throws -> String {
        let gpg = try GPGLocator.locate()
        return URL(fileURLWithPath: gpg)
            .deletingLastPathComponent()
            .appendingPathComponent(name)
            .path
    }

    // MARK: - Agent lifecycle

    /// Ensure gpg-agent is running. Safe to call repeatedly — `gpgconf --launch`
    /// is a no-op when the agent is already up.
    ///
    /// Call this before any GPG operation that may need a passphrase or card PIN
    /// so the agent socket exists before GPG tries to connect to it.
    private static let launchLock = NSLock()
    private static var lastLaunch: Date?
    /// How long a successful launch is trusted before checking again.
    private static let launchTrustWindow: TimeInterval = 60

    @discardableResult
    static func ensureRunning() throws -> Bool {
        // Called before every sign, encrypt, decrypt and verify. `gpgconf
        // --launch` is a no-op when the agent is up, but it is still a process
        // spawn per operation — and Mail can ask to decode the same mailbox
        // many times over. Trust a recent successful launch instead.
        launchLock.lock()
        let recentlyLaunched = lastLaunch.map {
            Date().timeIntervalSince($0) < launchTrustWindow
        } ?? false
        launchLock.unlock()
        if recentlyLaunched { return true }

        let gpgconf = try toolPath("gpgconf")
        guard FileManager.default.isExecutableFile(atPath: gpgconf) else {
            // Older GPG without gpgconf — agent auto-starts on first use.
            return false
        }
        let launched = run(gpgconf, args: ["--launch", "gpg-agent"])
        if launched {
            launchLock.lock()
            lastLaunch = Date()
            launchLock.unlock()
        }
        return launched
    }

    /// Kill the running agent and start a fresh one.
    /// Required after writing changes to gpg-agent.conf.
    static func restart() throws {
        let gpgconf = try toolPath("gpgconf")
        run(gpgconf, args: ["--kill", "gpg-agent"])
        launchLock.lock()
        lastLaunch = nil          // the agent we trusted is the one we just killed
        launchLock.unlock()
        try ensureRunning()
    }

    // MARK: - Pinentry configuration

    /// The URL of `~/.gnupg/gpg-agent.conf` (or `$GNUPGHOME/gpg-agent.conf`).
    static var agentConfURL: URL {
        let base = ProcessInfo.processInfo.environment["GNUPGHOME"]
            ?? (NSHomeDirectory() as NSString).appendingPathComponent(".gnupg")
        return URL(fileURLWithPath: base).appendingPathComponent("gpg-agent.conf")
    }

    /// Known locations for `pinentry-mac` — the native macOS pinentry GUI.
    static let macPinentryPaths = [
        "/opt/homebrew/bin/pinentry-mac",
        "/usr/local/bin/pinentry-mac",
        "/usr/local/MacGPG2/libexec/pinentry-mac.app/Contents/MacOS/pinentry-mac",
        "/Applications/GPG Keychain.app/Contents/Resources/pinentry-mac",
    ]

    /// The first `pinentry-mac` binary found on this machine, or `nil`.
    static var availableMacPinentry: String? {
        macPinentryPaths.first { FileManager.default.isExecutableFile(atPath: $0) }
    }

    /// The current pinentry configuration state.
    enum PinentryStatus: Equatable {
        /// A macOS-native pinentry is configured and the file exists. ✅
        case ok(path: String)
        /// A non-GUI pinentry is configured (e.g. pinentry-curses). Will hang. ⚠️
        case nonMac(configured: String, fix: String?)
        /// No `pinentry-program` line in the config; macOS pinentry available. ⚠️
        case fixable(path: String)
        /// No config line and no macOS pinentry found anywhere. ❌
        case notInstalled
    }

    /// Read `gpg-agent.conf` and classify the current pinentry setup.
    static func checkPinentry() -> PinentryStatus {
        let content = (try? String(contentsOf: agentConfURL, encoding: .utf8)) ?? ""

        // Take the LAST pinentry-program line, not the first: gpg-agent honours
        // the final occurrence of an option, so reporting on the first would
        // call a config healthy while the agent used a different, broken entry.
        var configured: String?
        for line in content.components(separatedBy: "\n") {
            let t = line.trimmingCharacters(in: .whitespaces)
            guard !t.hasPrefix("#"), t.hasPrefix("pinentry-program") else { continue }
            configured = String(t.dropFirst("pinentry-program".count))
                .trimmingCharacters(in: .whitespaces)
        }

        if let path = configured {
            let isMac = path.contains("pinentry-mac") || path.contains("pinentry-touchid")
            if isMac && FileManager.default.isExecutableFile(atPath: path) {
                return .ok(path: path)
            }
            return .nonMac(configured: path, fix: availableMacPinentry)
        }

        // No pinentry-program line at all.
        if let available = availableMacPinentry { return .fixable(path: available) }
        return .notInstalled
    }

    /// Write `pinentry-program <path>` to `gpg-agent.conf` and restart the agent.
    static func configurePinentry(path: String) throws {
        guard !path.contains("\n"), !path.contains("\r"), path.hasPrefix("/") else {
            throw GPGXPCError.make(.encodingFailed, message: "Invalid pinentry path")
        }

        // Read existing config (or start fresh).
        var lines = (try? String(contentsOf: agentConfURL, encoding: .utf8))?
            .components(separatedBy: "\n") ?? []

        // Remove any existing active pinentry-program line. Commented-out
        // lines are left alone — they start with '#', so they do not match, and
        // they are the user's own notes rather than live configuration.
        lines = lines.filter {
            !$0.trimmingCharacters(in: .whitespaces)
                .lowercased().hasPrefix("pinentry-program")
        }
        lines.append("pinentry-program \(path)")

        // Ensure ~/.gnupg exists.
        try FileManager.default.createDirectory(
            at: agentConfURL.deletingLastPathComponent(),
            withIntermediateDirectories: true)

        try lines.joined(separator: "\n")
            .write(to: agentConfURL, atomically: true, encoding: .utf8)

        try restart()
    }

    // MARK: - Private helpers

    @discardableResult
    private static func run(_ executable: String, args: [String]) -> Bool {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: executable)
        p.arguments = args
        var env = ProcessInfo.processInfo.environment
        env.removeValue(forKey: "DYLD_INSERT_LIBRARIES")
        p.environment = env
        p.standardOutput = FileHandle.nullDevice
        p.standardError  = FileHandle.nullDevice
        // `waitUntilExit()` raises if the process never launched, and the throw
        // from `run()` was being swallowed with `try?` — so a missing or
        // non-executable gpgconf took the host app down with an uncaught
        // exception instead of returning false. restart() reaches here without
        // checking the path first, which is exactly that case.
        do {
            try p.run()
        } catch {
            return false
        }
        p.waitUntilExit()
        return p.terminationStatus == 0
    }
}
