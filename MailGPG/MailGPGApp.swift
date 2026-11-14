// MailGPGApp.swift
// MailGPG

import SwiftUI

@main
struct MailGPGApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) var appDelegate

    var body: some Scene {
        // No scene windows: launchd runs the app headless as an XPC service,
        // and the AppDelegate shows the helper status when the user opens it.
        // Everything else happens in the Mail extension.
        Settings { EmptyView() }
    }
}
