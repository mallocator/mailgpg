// AppDelegate.swift
// MailGPG (host app only)

import AppKit
import SwiftUI
import os

class AppDelegate: NSObject, NSApplicationDelegate {

    /// Kept alive for the entire lifetime of the app.
    /// If this is deallocated, the XPC listener stops accepting connections.
    private var serviceListener: GPGServiceListener?

    private var statusWindow: NSWindow?

    private let environment = ProcessInfo.processInfo.environment

    func applicationDidFinishLaunching(_ notification: Notification) {
        if HelperRegistration.isHostingTests(environment: environment) { return }

        // Opened by the user: register the agent, show how that went, and
        // leave the serving to the copy launchd starts.
        guard HelperRegistration.isLaunchedAsAgent(environment: environment) else {
            showStatusWindow()
            return
        }

        let listener = GPGServiceListener()
        listener.start()
        serviceListener = listener

        // Start gpg-agent in the background so it is ready before the first
        // sign / decrypt operation.  Failures are non-fatal — the agent will
        // start on demand when GPG needs it; this just avoids the initial delay.
        DispatchQueue.global(qos: .background).async {
            _ = try? GPGAgent.ensureRunning()
        }
    }

    /// Opening the app while the agent runs reaches the agent instead of
    /// starting a new copy. It hands over to a new copy in the user role, so
    /// that copy can replace an agent started by a legacy plist. Opening it
    /// while a status window is up registers again in a fresh window, so a
    /// window from an earlier run can't show an outdated result.
    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        guard serviceListener != nil else {
            showStatusWindow()
            return false
        }
        let configuration = NSWorkspace.OpenConfiguration()
        configuration.createsNewApplicationInstance = true
        NSWorkspace.shared.openApplication(at: Bundle.main.bundleURL, configuration: configuration) { _, error in
            if let error {
                log.error("could not open the registration window: \(error.localizedDescription, privacy: .public)")
            }
        }
        return false
    }

    /// Only the copy the user opened quits with its window; the agent and a
    /// test host keep running.
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        statusWindow != nil
    }

    private func showStatusWindow() {
        // The new window comes up before the old one closes, or closing the
        // last window would quit the app.
        let previous = statusWindow
        let window = Self.makeStatusWindow(HelperStatusView())
        window.center()
        window.makeKeyAndOrderFront(nil)
        statusWindow = window
        previous?.close()
        NSApp.activate()
    }

    /// A fixed-size window: the view sets its width, the content its height.
    static func makeStatusWindow(_ view: HelperStatusView) -> NSWindow {
        let window = NSWindow(contentViewController: NSHostingController(rootView: view))
        window.title = "MailGPG"
        window.styleMask = [.titled, .closable]
        window.isReleasedWhenClosed = false
        return window
    }
}
