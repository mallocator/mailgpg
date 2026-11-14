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
    /// that copy can replace an agent started by a legacy plist.
    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        guard serviceListener != nil else { return true }
        let configuration = NSWorkspace.OpenConfiguration()
        configuration.createsNewApplicationInstance = true
        NSWorkspace.shared.openApplication(at: Bundle.main.bundleURL, configuration: configuration) { _, error in
            if let error {
                log.error("could not open the registration window: \(error.localizedDescription, privacy: .public)")
            }
        }
        return false
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        serviceListener == nil
    }

    private func showStatusWindow() {
        let window = NSWindow(contentViewController: NSHostingController(rootView: HelperStatusView()))
        window.title = "MailGPG"
        window.styleMask = [.titled, .closable]
        window.isReleasedWhenClosed = false
        window.center()
        window.makeKeyAndOrderFront(nil)
        statusWindow = window
        NSApp.activate()
    }
}
