// HelperStatusView.swift
// MailGPG (host app only)

import ServiceManagement
import SwiftUI

/// The window the app shows when the user opens it: registers the helper and
/// says whether the Mail extension can reach it.
struct HelperStatusView: View {

    @State private var checking = true
    @State private var status: SMAppService.Status = .notRegistered
    @State private var error: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            if checking {
                HStack {
                    ProgressView().controlSize(.small)
                    Text("Registering the helper…")
                }
            } else {
                switch status {
                case .enabled:
                    Label("The helper is running and starts at every login.", systemImage: "checkmark.circle.fill")
                        .foregroundStyle(.green)
                    Text("Enable the extension in Mail → Settings → Extensions → MailGPG. You can close this window.")
                        .foregroundStyle(.secondary)
                case .requiresApproval:
                    Label("The helper is switched off in Login Items.", systemImage: "exclamationmark.triangle.fill")
                        .foregroundStyle(.orange)
                    Text("Turn on MailGPG under System Settings → General → Login Items, then check again.")
                        .foregroundStyle(.secondary)
                    Button("Open Login Items") { SMAppService.openSystemSettingsLoginItems() }
                default:
                    Label("The helper could not be registered.", systemImage: "xmark.circle.fill")
                        .foregroundStyle(.red)
                    Text(error ?? "macOS did not find the launch agent in MailGPG.app. Reinstall the app.")
                        .foregroundStyle(.secondary)
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
        let result = await HelperRegistration.ensureRegistered()
        status = result.status
        error = result.error
        checking = false
    }
}
