// HelperRegistrationTests.swift
// MailGPGTests

import ServiceManagement
import XCTest
@testable import MailGPG

final class HelperRegistrationTests: XCTestCase {

    // MARK: - Launch role

    func testLaunchedAsAgent_byOurLabel() {
        XCTAssertTrue(HelperRegistration.isLaunchedAsAgent(environment: ["XPC_SERVICE_NAME": "net.pyxzl.mailgpg"]))
    }

    func testLaunchedByUser_fromFinder() {
        let env = ["XPC_SERVICE_NAME": "application.net.pyxzl.MailGPG.1234.5678"]
        XCTAssertFalse(HelperRegistration.isLaunchedAsAgent(environment: env))
        XCTAssertFalse(HelperRegistration.isLaunchedAsAgent(environment: [:]))
    }

    func testHostingTests_whileTheseRun() {
        XCTAssertTrue(HelperRegistration.isHostingTests(environment: ProcessInfo.processInfo.environment))
        XCTAssertFalse(HelperRegistration.isHostingTests(environment: [:]))
    }

    // MARK: - Steps

    func testFreshInstall_registers() {
        XCTAssertEqual(HelperRegistration.steps(legacyPlistExists: false, status: .notRegistered, jobLoaded: false),
                       [.register])
    }

    func testRegisteredAndRunning_doesNothing() {
        XCTAssertEqual(HelperRegistration.steps(legacyPlistExists: false, status: .enabled, jobLoaded: true), [])
    }

    func testRegisteredButStopped_registersAgain() {
        // A cask upgrade or uninstall runs `launchctl remove`, which leaves
        // the registration in place but the job unloaded.
        XCTAssertEqual(HelperRegistration.steps(legacyPlistExists: false, status: .enabled, jobLoaded: false),
                       [.unregister, .register])
    }

    func testLegacyPlist_isStoppedAndRemovedBeforeRegistering() {
        XCTAssertEqual(HelperRegistration.steps(legacyPlistExists: true, status: .notRegistered, jobLoaded: true),
                       [.removeLegacyPlist, .bootOut, .register])
    }

    func testLegacyPlistNextToRegistration_endsWithOneJob() {
        // The loaded job may be either one; after the boot-out neither runs.
        XCTAssertEqual(HelperRegistration.steps(legacyPlistExists: true, status: .enabled, jobLoaded: true),
                       [.removeLegacyPlist, .bootOut, .unregister, .register])
    }

    func testSwitchedOffInLoginItems_leavesItToTheUser() {
        XCTAssertEqual(HelperRegistration.steps(legacyPlistExists: false, status: .requiresApproval, jobLoaded: false),
                       [])
        XCTAssertEqual(HelperRegistration.steps(legacyPlistExists: true, status: .requiresApproval, jobLoaded: true),
                       [.removeLegacyPlist, .bootOut])
    }

    // MARK: - Outcome

    func testEnabledAndRunning_isRunning() {
        XCTAssertEqual(HelperRegistration.outcome(status: .enabled, jobRunning: true), .running)
    }

    func testEnabledButNotRunning_isNotReportedAsRunning() {
        // Registered with SMAppService, but launchd has not started the job.
        XCTAssertEqual(HelperRegistration.outcome(status: .enabled, jobRunning: false), .notRunning)
    }

    func testSwitchedOff_needsApproval() {
        XCTAssertEqual(HelperRegistration.outcome(status: .requiresApproval, jobRunning: false), .requiresApproval)
        // A job left by a legacy plist does not make it registered.
        XCTAssertEqual(HelperRegistration.outcome(status: .requiresApproval, jobRunning: true), .requiresApproval)
    }

    func testNotRegistered_failed() {
        XCTAssertEqual(HelperRegistration.outcome(status: .notRegistered, jobRunning: true), .failed)
        XCTAssertEqual(HelperRegistration.outcome(status: .notFound, jobRunning: false), .failed)
    }

    func testJobRunning_readsThePIDFromLaunchctlPrint() {
        let running = """
            gui/501/net.pyxzl.mailgpg = {
            \tactive count = 1
            \tstate = running
            \tprogram identifier = Contents/MacOS/MailGPG (mode: 2)
            \tpid = 4242
            \timmediate reason = speculative
            }
            """
        XCTAssertTrue(HelperRegistration.jobRunning(launchctlPrint: running))
    }

    func testJobRunning_loadedWithoutPID_isNotRunning() {
        let waiting = """
            gui/501/net.pyxzl.mailgpg = {
            \tactive count = 0
            \tstate = not running
            \tlast exit code = 78: EX_CONFIG
            \tparent pid = 1
            }
            """
        XCTAssertFalse(HelperRegistration.jobRunning(launchctlPrint: waiting))
        XCTAssertFalse(HelperRegistration.jobRunning(launchctlPrint: ""))
    }

    // MARK: - Bundled plist

    func testBundledPlist_runsTheAppFromItsBundle() throws {
        let url = Bundle.main.bundleURL
            .appendingPathComponent("Contents/Library/LaunchAgents/\(HelperRegistration.plistName)")
        let data = try Data(contentsOf: url)
        let plist = try XCTUnwrap(PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any])

        XCTAssertEqual(plist["Label"] as? String, HelperRegistration.label)
        XCTAssertEqual(plist["AssociatedBundleIdentifiers"] as? String, Bundle.main.bundleIdentifier)
        XCTAssertEqual(plist["BundleProgram"] as? String, "Contents/MacOS/MailGPG")
        XCTAssertNil(plist["ProgramArguments"], "an absolute path breaks when the app moves")
        XCTAssertEqual(plist["KeepAlive"] as? Bool, true)
        let services = try XCTUnwrap(plist["MachServices"] as? [String: Bool])
        XCTAssertEqual(services, [GPGServiceName: true])
    }
}
