// HelperStatusWindowTests.swift
// MailGPGTests

import AppKit
import XCTest
@testable import MailGPG

/// Opens the status window the app shows, in this test host, with a stubbed
/// registration in each of its states. Screenshots are attached to the test
/// result; with `TEST_RUNNER_MAILGPG_SCREENSHOTS=<folder>` set for
/// `xcodebuild test` they are also written there as PNG files.
@MainActor
final class HelperStatusWindowTests: XCTestCase {

    private typealias Registration = (outcome: HelperRegistration.Outcome, error: String?)

    func testEveryState_fitsTheFixedWidthWindow() throws {
        let states: [(name: String, register: () async -> Registration)] = [
            ("checking", {
                try? await Task.sleep(for: .seconds(3600))
                return (.failed, nil)
            }),
            ("running", { (.running, nil) }),
            ("not-running", { (.notRunning, nil) }),
            ("requires-approval", { (.requiresApproval, nil) }),
            ("failed", { (.failed, nil) }),
            ("failed-with-error", { (.failed, "The operation couldn’t be completed. Operation not permitted") }),
        ]
        for state in states {
            for (mode, appearance) in [("light", NSAppearance.Name.aqua), ("dark", NSAppearance.Name.darkAqua)] {
                let window = AppDelegate.makeStatusWindow(HelperStatusView(ensureRegistered: state.register))
                window.appearance = NSAppearance(named: appearance)
                window.orderFrontRegardless()
                RunLoop.main.run(until: Date().addingTimeInterval(0.5))

                // Not resizable, so one width covers every screen size.
                XCTAssertFalse(window.styleMask.contains(.resizable))
                XCTAssertEqual(window.contentLayoutRect.width, 420)

                let frameView = try XCTUnwrap(window.contentView?.superview)
                let rep = try XCTUnwrap(frameView.bitmapImageRepForCachingDisplay(in: frameView.bounds))
                frameView.cacheDisplay(in: frameView.bounds, to: rep)
                let png = try XCTUnwrap(rep.representation(using: .png, properties: [:]))
                save(png, name: "status-window-\(state.name)-\(mode)")
                window.close()
            }
        }
    }

    private func save(_ png: Data, name: String) {
        let attachment = XCTAttachment(data: png, uniformTypeIdentifier: "public.png")
        attachment.name = "\(name).png"
        attachment.lifetime = .keepAlways
        add(attachment)

        guard let folder = ProcessInfo.processInfo.environment["MAILGPG_SCREENSHOTS"] else { return }
        let url = URL(fileURLWithPath: folder).appendingPathComponent("\(name).png")
        XCTAssertNoThrow(try png.write(to: url))
    }
}
