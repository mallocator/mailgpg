//
//  MailExtension.swift
//  MailGPGExtension
//
//  Created by Marcel Haupt on 17.03.26.
//

import MailKit
import os

private let log = Logger(subsystem: "net.pyxzl.mailgpg", category: "extension")

class MailExtension: NSObject, MEExtension {
    func handlerForMessageActions() -> MEMessageActionHandler {
        // Logged so "Mail never asked for the handler" can be told apart from
        // "Mail asked for it and never called it" — the two have completely
        // different causes and the symptom is identical.
        log.info("handlerForMessageActions requested")
        return MessageActionHandler.shared
    }

    func handler(for session: MEComposeSession) -> MEComposeSessionHandler {
        // Create a unique instance, since each compose window is separate.
        return ComposeSessionHandler()
    }

    func handlerForMessageSecurity() -> MEMessageSecurityHandler {
        // Use a shared instance for all messages, since there's
        // no state associated with the security handler.
        return MessageSecurityHandler.shared
    }

}

