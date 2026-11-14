// HelperStatusView.swift
// MailGPG (host app only)

import ServiceManagement
import SwiftUI

/// The window the app shows when the user opens it: registers the helper and
/// says whether the Mail extension can reach it.
struct HelperStatusView: View {

    /// Registers the helper and reports what came of it; tests pass a stub
    /// so showing the window leaves the installed helper alone.
    var ensureRegistered: () async -> (outcome: HelperRegistration.Outcome, error: String?) =
        HelperRegistration.ensureRegistered

    @State private var checking = true
    @State private var outcome: HelperRegistration.Outcome = .failed
    @State private var error: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            if checking {
                HStack {
                    ProgressView().controlSize(.small)
                    Text("Registering the helper…")
                }
            } else {
                switch outcome {
                case .running:
                    Label("The helper is running and starts at every login.", systemImage: "checkmark.circle.fill")
                        .foregroundStyle(.green)
                    Text("Enable the extension in Mail → Settings → Extensions → MailGPG. You can close this window.")
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                case .notRunning:
                    Label("The helper is registered but not running.", systemImage: "exclamationmark.triangle.fill")
                        .foregroundStyle(.orange)
                    Text("launchd has not started it yet. Check again in a moment; if it stays like this, log out and back in.")
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                case .requiresApproval:
                    Label("The helper is switched off in Login Items.", systemImage: "exclamationmark.triangle.fill")
                        .foregroundStyle(.orange)
                    Text("Turn on MailGPG under System Settings → General → Login Items, then check again.")
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                    Button("Open Login Items") { SMAppService.openSystemSettingsLoginItems() }
                case .failed:
                    Label("The helper could not be registered.", systemImage: "xmark.circle.fill")
                        .foregroundStyle(.red)
                    Text(error ?? "macOS did not find the launch agent in MailGPG.app. Reinstall the app.")
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                Button("Check Again") { Task { await register() } }
            }
        }
        .padding(20)
        .frame(width: 420, alignment: .leading)
        .task { await register() }
    }

    private func register() async {
        checking = true
        let result = await ensureRegistered()
        outcome = result.outcome
        error = result.error
        checking = false
    }
}
