// GPGServiceListener.swift
// MailGPG (host app only)

import Foundation
import os

/// The Mach service name both sides must agree on.
/// Think of it like a port number — the extension dials this name,
/// the host app listens on it.
let GPGServiceName = "net.pyxzl.mailgpg.gpgservice"

/// Sets up and runs the XPC listener on the host-app side.
///
/// `NSXPCListener` is the server half of XPC. When the extension calls
/// `NSXPCConnection(machServiceName:)`, the OS routes that connection
/// request here. We then decide whether to accept it.
final class GPGServiceListener: NSObject, NSXPCListenerDelegate {

    private let listener: NSXPCListener

    override init() {
        listener = NSXPCListener(machServiceName: GPGServiceName)
        super.init()
        listener.delegate = self
    }

    /// Call once at app launch. The listener runs until the app quits.
    func start() {
        listener.resume()
        log.info("listener started on \(GPGServiceName, privacy: .public)")
    }

    // MARK: - NSXPCListenerDelegate

    /// Called by XPC for every incoming connection attempt.
    /// Return `true` to accept, `false` to reject.
    func listener(
        _ listener: NSXPCListener,
        shouldAcceptNewConnection connection: NSXPCConnection
    ) -> Bool {

        // Security check: only accept connections from our own extension.
        // Without this, any app on the machine could ask us to run GPG.
        guard isConnectionFromOurExtension(connection) else {
            // Worth an error rather than a debug line: on a healthy machine this
              // never happens, and when it does it is either a broken install or
              // something local trying to use our keys.
            log.error("rejected XPC connection from a client that does not match our signing identity")
            return false
        }

        // Tell XPC what protocol the remote side (extension) can call on us.
        connection.exportedInterface = NSXPCInterface(with: GPGXPCProtocol.self)

        // The object that actually handles the calls — created fresh per connection.
        connection.exportedObject = GPGServiceImpl()

        // Must call resume() or the connection stays suspended and nothing works.
        connection.resume()

        log.info("accepted XPC connection from the Mail extension")
        return true
    }

    // MARK: - Security validation

    private func isConnectionFromOurExtension(_ connection: NSXPCConnection) -> Bool {
        // We validate the connecting process by its code-signing identity.
        // `processIdentifier` gives us the PID; we hand that to the Security
        // framework which looks up the running process and checks its signature.
        //
        // Note: PID-based lookup has a theoretical TOCTOU race (the process
        // could be replaced between connection and validation), but this is
        // acceptable for validating our own extension on the same machine.
        // A bundle identifier on its own is a self-declared string: ANY binary,
        // ad-hoc signed by anyone, can claim it and satisfy `identifier "..."`.
        // Without the anchor and team-ID clauses below, any process running as
        // the user could open this Mach service and use it as a signing and
        // decryption oracle — silently, because gpg-agent caches the passphrase.
        //
        //   anchor apple generic  → the cert chain really is an Apple-issued one
        //   subject.OU            → the leaf cert belongs to our Developer team
        //
        // Both "Apple Development" and "Developer ID Application" certificates
        // carry the team ID in the leaf OU, so this holds for local debug builds
        // and notarised release builds alike.
        let requirement = """
            identifier "net.pyxzl.MailGPG.MailGPGExtension" \
            and anchor apple generic \
            and certificate leaf[subject.OU] = "3HKD37M482"
            """
        let pid = connection.processIdentifier

        var secCode: SecCode?
        let attrs = [kSecGuestAttributePid: pid] as CFDictionary

        guard SecCodeCopyGuestWithAttributes(nil, attrs, [], &secCode) == errSecSuccess,
              let code = secCode else {
            return false
        }

        var secRequirement: SecRequirement?
        guard SecRequirementCreateWithString(requirement as CFString, [], &secRequirement) == errSecSuccess,
              let req = secRequirement else {
            return false
        }

        return SecCodeCheckValidity(code, [], req) == errSecSuccess
    }
}
