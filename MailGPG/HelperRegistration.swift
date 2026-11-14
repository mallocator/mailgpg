// HelperRegistration.swift
// MailGPG (host app only)

import Foundation
import ServiceManagement
import os

/// Registers the bundled launch agent with `SMAppService`, so the copy of
/// this app that launchd starts is the one serving the Mail extension.
///
/// The same binary runs in two roles. launchd starts it as the agent, which
/// listens on the Mach service; the user opens it from Finder, which registers
/// the agent and shows its state. The plist the agent runs from ships in the
/// bundle at `Contents/Library/LaunchAgents`.
enum HelperRegistration {

    static let label = "net.pyxzl.mailgpg"
    static let plistName = "\(label).plist"

    static var service: SMAppService { SMAppService.agent(plistName: plistName) }

    /// The registration as Diagnostics in the extension shows it.
    static var state: HelperRegistrationState { HelperRegistrationState(service.status) }

    /// Where older casks and build.sh wrote the agent plist themselves.
    static var legacyPlistURL: URL {
        FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/LaunchAgents/\(plistName)")
    }

    // MARK: - Launch role

    /// launchd sets `XPC_SERVICE_NAME` to the job label in the processes it
    /// starts; an app opened from Finder gets `application.<bundle id>.…`.
    /// Both the bundled agent and a plist left by an older install carry our
    /// label, so either one counts as the agent.
    static func isLaunchedAsAgent(environment: [String: String]) -> Bool {
        environment["XPC_SERVICE_NAME"] == label
    }

    /// Xcode launches this app as the host of the unit tests. Registering a
    /// login item from a DerivedData build would replace the installed one.
    static func isHostingTests(environment: [String: String]) -> Bool {
        environment["XCTestConfigurationFilePath"] != nil
    }

    // MARK: - Steps

    enum Step: Equatable {
        /// Delete the plist an older install wrote to ~/Library/LaunchAgents.
        case removeLegacyPlist
        /// Stop whichever job holds our label.
        case bootOut
        case unregister
        case register
    }

    /// What it takes to end with exactly one job, started from the bundle.
    ///
    /// The legacy job and the bundled one share the label and Mach service,
    /// and launchd loads only one of them, so the legacy one is stopped and
    /// its plist deleted before registering. A registered agent that is not
    /// loaded (a cask upgrade or uninstall stopped it) is registered again,
    /// which is the only way `SMAppService` starts it.
    static func steps(legacyPlistExists: Bool, status: SMAppService.Status, jobLoaded: Bool) -> [Step] {
        let migration: [Step] = legacyPlistExists ? [.removeLegacyPlist, .bootOut] : []
        let loaded = jobLoaded && !legacyPlistExists
        switch status {
        case .enabled:
            return migration + (loaded ? [] : [.unregister, .register])
        case .requiresApproval:
            // Registered but switched off in Login Items: only the user can
            // turn it back on.
            return migration
        case .notRegistered, .notFound:
            return migration + [.register]
        @unknown default:
            return migration + [.register]
        }
    }

    // MARK: - Running them

    /// Brings the registration to the state `steps` describes and returns the
    /// status afterwards, with the error of a failed `register()`, if any.
    static func ensureRegistered() async -> (status: SMAppService.Status, error: String?) {
        let fileManager = FileManager.default
        let before = service.status
        let plan = steps(
            legacyPlistExists: fileManager.fileExists(atPath: legacyPlistURL.path),
            status: before,
            jobLoaded: launchctl("print", "gui/\(getuid())/\(label)"))
        log.info("helper registration: status=\(String(describing: before), privacy: .public) steps=\(String(describing: plan), privacy: .public)")

        var registerError: String?
        for step in plan {
            switch step {
            case .removeLegacyPlist:
                do {
                    try fileManager.removeItem(at: legacyPlistURL)
                } catch {
                    log.error("could not remove \(legacyPlistURL.path, privacy: .public): \(error.localizedDescription, privacy: .public)")
                }
            case .bootOut:
                _ = launchctl("bootout", "gui/\(getuid())/\(label)")
            case .unregister:
                do {
                    try await service.unregister()
                } catch {
                    log.info("unregister before re-registering: \(error.localizedDescription, privacy: .public)")
                }
            case .register:
                do {
                    try service.register()
                } catch {
                    // An agent switched off in Login Items fails here; the
                    // status below tells the user what to do about it.
                    log.error("register failed: \(error.localizedDescription, privacy: .public)")
                    registerError = error.localizedDescription
                }
            }
        }
        let status = service.status
        return (status, status == .enabled ? nil : registerError)
    }

    /// Runs `/bin/launchctl` with its output discarded; `true` on exit status 0.
    private static func launchctl(_ arguments: String...) -> Bool {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/launchctl")
        process.arguments = arguments
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        do {
            try process.run()
        } catch {
            log.error("launchctl \(arguments.joined(separator: " "), privacy: .public): \(error.localizedDescription, privacy: .public)")
            return false
        }
        process.waitUntilExit()
        return process.terminationStatus == 0
    }
}

extension HelperRegistrationState {
    init(_ status: SMAppService.Status) {
        switch status {
        case .enabled: self = .enabled
        case .requiresApproval: self = .requiresApproval
        case .notRegistered: self = .notRegistered
        case .notFound: self = .notFound
        @unknown default: self = .notFound
        }
    }
}
