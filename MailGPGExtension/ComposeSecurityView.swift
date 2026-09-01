// ComposeSecurityView.swift
// MailGPGExtension

import Combine
import MailKit
import SwiftUI

// MARK: - Shared store

/// Singleton that owns all per-session states so both ComposeSessionHandler
/// and MessageSecurityHandler can read the same sign/encrypt toggles.
final class ComposeStateStore {
    static let shared = ComposeStateStore()

    private var states: [UUID: ComposeSessionState] = [:]
    /// The dictionary is written from Mail's compose callbacks and read from
    /// the async recipient-annotation task and from the security handler, which
    /// are not the same thread. A Swift Dictionary read concurrently with a
    /// write is undefined behaviour, and the failure mode is a crash inside
    /// Mail rather than anything that looks like it came from here.
    private let lock = NSLock()

    @discardableResult
    func register(_ session: MEComposeSession) -> ComposeSessionState {
        let state = ComposeSessionState()
        lock.lock()
        states[session.sessionID] = state
        lock.unlock()
        return state
    }

    func state(for sessionID: UUID) -> ComposeSessionState? {
        lock.lock()
        defer { lock.unlock() }
        return states[sessionID]
    }

    func remove(_ sessionID: UUID) {
        lock.lock()
        states.removeValue(forKey: sessionID)
        lock.unlock()
    }

    /// Best-effort: returns the state for the only active session, or nil if ambiguous.
    var singleActiveState: ComposeSessionState? {
        lock.lock()
        defer { lock.unlock() }
        return states.count == 1 ? states.values.first : nil
    }

    /// Whether any compose window is still open. Used to decide whether cached
    /// outgoing-message state is still needed.
    var isEmpty: Bool {
        lock.lock()
        defer { lock.unlock() }
        return states.isEmpty
    }
}

// MARK: - Shared state

/// Observable state shared between ComposeSessionHandler and ComposeSecurityView.
/// One instance is created per compose session.
final class ComposeSessionState: ObservableObject {
    /// Per-recipient key availability. Keyed by email address (lowercased).
    @Published var recipientKeyStatus: [String: RecipientKeyStatus] = [:]
    /// The `KeyInfo` for each recipient that has a key. Keyed by email address (lowercased).
    /// Used by `MessageSecurityHandler` to get fingerprints for encryption.
    @Published var recipientKeys: [String: KeyInfo] = [:]
    /// Prepared Autocrypt header value for this compose session, or nil when
    /// the feature is off or the sender has no usable key. Computed when the
    /// session opens so `additionalHeaders` — which must answer synchronously —
    /// has it ready by send time.
    @Published var autocryptHeader: String?

    /// Encryption is only possible when every recipient has a known public key.
    var canEncrypt: Bool {
        !recipientKeyStatus.isEmpty &&
        recipientKeyStatus.values.allSatisfy { $0 == .found }
    }
}

enum RecipientKeyStatus: Equatable {
    case found
    case notFound
    /// A key exists, but it is not the one last used for this address.
    case keyChanged
    case loading
}

// MARK: - View

struct ComposeSecurityView: View {
    @ObservedObject var state: ComposeSessionState
    @State private var hostAppAvailable: Bool? = nil

    var body: some View {
        NavigationStack {
            VStack(alignment: .leading, spacing: 12) {
                if hostAppAvailable == false {
                    HStack(spacing: 8) {
                        Image(systemName: "exclamationmark.triangle.fill")
                            .foregroundStyle(.yellow)
                        Text("MailGPG host app is not running. Open it to enable GPG operations.")
                            .font(.caption)
                            .foregroundStyle(.primary)
                    }
                    .padding(10)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(.yellow.opacity(0.15), in: RoundedRectangle(cornerRadius: 8))
                }

                Text("OpenPGP")
                    .font(.headline)

                Divider()

                // Status indicators
                HStack(spacing: 10) {
                    Image(systemName: "signature")
                        .foregroundStyle(.blue)
                        .frame(width: 20, alignment: .center)
                    VStack(alignment: .leading, spacing: 1) {
                        Text("Signing available")
                            .font(.callout)
                    }
                    Spacer()
                    Image(systemName: "checkmark.circle.fill")
                        .foregroundStyle(.green)
                }

                HStack(spacing: 10) {
                    Image(systemName: state.canEncrypt ? "lock.fill" : "lock.open")
                        .foregroundStyle(state.canEncrypt ? .green : .secondary)
                        .frame(width: 20, alignment: .center)
                    VStack(alignment: .leading, spacing: 1) {
                        Text(state.canEncrypt ? "Encryption available" : "Encryption unavailable")
                            .font(.callout)
                        if !state.canEncrypt && !state.recipientKeyStatus.isEmpty {
                            Text("Some recipients are missing a public key.")
                                .font(.caption2)
                                .foregroundStyle(.orange)
                        }
                    }
                    Spacer()
                    Image(systemName: state.canEncrypt ? "checkmark.circle.fill" : "xmark.circle.fill")
                        .foregroundStyle(state.canEncrypt ? .green : .orange)
                }

                Text("Use Mail's toolbar buttons to sign or encrypt.")
                    .font(.caption2)
                    .foregroundStyle(.secondary)

                // Recipient key status list
                if !state.recipientKeyStatus.isEmpty {
                    Divider()

                    VStack(alignment: .leading, spacing: 6) {
                        Text("Recipients")
                            .font(.caption)
                            .foregroundStyle(.secondary)

                        ForEach(
                            state.recipientKeyStatus.sorted(by: { $0.key < $1.key }),
                            id: \.key
                        ) { email, keyStatus in
                            RecipientRow(email: email,
                                         status: keyStatus,
                                         key: state.recipientKeys[email])
                        }
                    }
                }

                Divider()

                PGPOptionsToggles()

                NavigationLink {
                    KeyManagementView()
                } label: {
                    Label("Manage Keys", systemImage: "key.2.on.ring")
                        .font(.callout)
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.borderless)

                NavigationLink {
                    KeyserverSettingsView()
                } label: {
                    Label("Keyservers", systemImage: "server.rack")
                        .font(.callout)
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.borderless)

                NavigationLink {
                    DiagnosticsView()
                } label: {
                    Label("Diagnostics", systemImage: "stethoscope")
                        .font(.callout)
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.borderless)
            }
            .padding(.horizontal)
            .padding(.top, 40)
            .padding(.bottom, 40)
            .frame(minWidth: 280)
            .task {
                do {
                    _ = try await GPGService.shared.ping()
                    hostAppAvailable = true
                } catch {
                    hostAppAvailable = false
                }
            }
        }
    }
}

// MARK: - Subviews

/// The three policy switches, in their own view.
///
/// Not a style choice: SwiftUI type-checks a view body as one expression, and
/// folding these into the main VStack — three modifier chains whose `.help`
/// text was built with string concatenation — pushed it past the compiler's
/// budget and failed the build outright. Small bodies and plain literals.
private struct PGPOptionsToggles: View {
    @State private var knownOnly: Bool = GPGService.shared.getKnownCorrespondentsOnly()
    @State private var autocryptEnabled: Bool = GPGService.shared.getAutocryptEnabled()
    @State private var protectSubject: Bool = GPGService.shared.getProtectSubject()

    private static let knownOnlyHelp = """
        Signing and encryption are offered only for people who have sent you PGP \
        mail, who publish a key through Web Key Directory, or who you have \
        encrypted to before. Stops signed mail reaching clients that show it as a \
        cryptic attachment, and stops encryption to keys nobody has used in years.
        """

    private static let autocryptHelp = """
        Adds your public key to outgoing mail as an Autocrypt header, and picks up \
        correspondents' keys from the mail they send you — so key exchange happens \
        through the correspondence instead of a keyserver.
        """

    private static let protectSubjectHelp = """
        Moves the Subject into the encrypted part of the message. Recipients whose \
        mail client does not support protected headers will see "..." instead.
        """

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Toggle("Only offer PGP to known correspondents", isOn: $knownOnly)
                .onChange(of: knownOnly) { _, value in
                    GPGService.shared.setKnownCorrespondentsOnly(value)
                }
                .help(Self.knownOnlyHelp)

            Toggle("Attach my key (Autocrypt)", isOn: $autocryptEnabled)
                .onChange(of: autocryptEnabled) { _, value in
                    GPGService.shared.setAutocryptEnabled(value)
                }
                .help(Self.autocryptHelp)

            Toggle("Hide subject line", isOn: $protectSubject)
                .onChange(of: protectSubject) { _, value in
                    GPGService.shared.setProtectSubject(value)
                }
                .help(Self.protectSubjectHelp)
        }
        .font(.callout)
        .toggleStyle(.checkbox)
    }
}

private struct RecipientRow: View {
    let email: String
    let status: RecipientKeyStatus
    /// The key that would actually be used. Nil while loading or when none was found.
    let key: KeyInfo?

    /// A key is only worth a green badge once it has been verified locally.
    /// Anything auto-fetched from a keyserver starts out unverified, and the UI
    /// must say so — encryption runs with `--trust-model always`, so nothing
    /// else in the pipeline will.
    private var verified: Bool { key?.trusted ?? false }

    var body: some View {
        HStack(spacing: 6) {
            icon
            Text(email)
                .font(.caption)
                .textSelection(.enabled)
                .lineLimit(1)
            Spacer()
            statusLabel
        }
    }

    @ViewBuilder
    private var icon: some View {
        switch status {
        case .found:
            Image(systemName: verified ? "key.fill" : "key")
                .font(.caption)
                .foregroundStyle(verified ? Color.green : Color.orange)
        case .keyChanged:
            Image(systemName: "exclamationmark.triangle.fill")
                .font(.caption)
                .foregroundStyle(Color.red)
        case .notFound:
            Image(systemName: "key.slash")
                .font(.caption)
                .foregroundStyle(.orange)
        case .loading:
            ProgressView()
                .controlSize(.mini)
        }
    }

    @ViewBuilder
    private var statusLabel: some View {
        switch status {
        case .found:
            VStack(alignment: .trailing, spacing: 0) {
                Text(key?.keyID ?? "Key found")
                    .font(.caption2)
                    .monospaced()
                    .textSelection(.enabled)
                    .foregroundStyle(verified ? Color.green : Color.orange)
                Text(verified ? "verified" : "unverified")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
            }
        case .keyChanged:
            VStack(alignment: .trailing, spacing: 0) {
                Text(key?.keyID ?? "changed")
                    .font(.caption2)
                    .monospaced()
                    .textSelection(.enabled)
                    .foregroundStyle(Color.red)
                Text("key changed")
                    .font(.caption2)
                    .foregroundStyle(Color.red)
            }
        case .notFound:
            Text("No key")
                .font(.caption2)
                .foregroundStyle(.orange)
        case .loading:
            Text("Looking up…")
                .font(.caption2)
                .foregroundStyle(.secondary)
        }
    }
}

// MARK: - Previews

#Preview("All keys found") {
    let state = ComposeSessionState()
    state.recipientKeyStatus = [
        "alice@example.com": .found,
        "bob@example.com": .found,
    ]
    return ComposeSecurityView(state: state)
}

#Preview("Missing key") {
    let state = ComposeSessionState()
    state.recipientKeyStatus = [
        "alice@example.com": .found,
        "carol@example.com": .notFound,
    ]
    return ComposeSecurityView(state: state)
}

#Preview("No recipients yet") {
    ComposeSecurityView(state: ComposeSessionState())
}
