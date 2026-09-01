# MailGPG — Ravi's fork, setup runbook

Branch `pyxzl`. Rebranded to `net.pyxzl` / team `3HKD37M482`, plus four fixes on
top of upstream `b8afeba`. Nothing here has been compiled — I have no Xcode in
this environment — so step 5 is where you find out whether my patches build.

Run everything from `~/Development/apple-mail-pgp/mailgpg`.

---

## 1. Install the dependencies

```bash
brew install gnupg pinentry-mac
```

Verify:

```bash
gpg --version | head -1
ls -l "$(brew --prefix)/bin/pinentry-mac"
```

## 2. Get the key out of 1Password

If the key is stored as a document/attachment, use the 1Password app: open the
item, download the attachment, and note where it landed. If you have the CLI
signed in, this is faster — replace the item name with yours:

```bash
op item list --categories "Secure Note,Document" | grep -i pgp
op document get "<item name>" --out-file ~/Desktop/secret.asc
```

If the key is stored as a plain text field rather than a document:

```bash
op read "op://Private/<item name>/private key" > ~/Desktop/secret.asc
```

Sanity-check that you got a private key and not a public one — the first line
must say PRIVATE:

```bash
head -1 ~/Desktop/secret.asc
```

## 3. Import it into the keyring

```bash
gpg --import ~/Desktop/secret.asc
gpg --list-secret-keys --keyid-format=long
```

Take the 40-character fingerprint from that output and mark your own key
ultimately trusted, which is what makes it usable for signing without prompts
and what makes the compose panel show it as verified:

```bash
FPR=<paste the 40-char fingerprint>
echo "${FPR}:6:" | gpg --import-ownertrust
gpg --check-trustdb
```

Then shred the transfer copy:

```bash
rm -P ~/Desktop/secret.asc
```

## 4. Make the passphrase prompt work (and stop asking)

The host app runs as a background agent with no terminal, so GPG's default
prompt cannot appear and signing fails silently without this:

```bash
mkdir -p ~/.gnupg && chmod 700 ~/.gnupg
grep -q pinentry-program ~/.gnupg/gpg-agent.conf 2>/dev/null \
  || echo "pinentry-program $(brew --prefix)/bin/pinentry-mac" >> ~/.gnupg/gpg-agent.conf
gpgconf --kill gpg-agent
```

Test it — a graphical prompt should appear:

```bash
echo test | gpg --clearsign --local-user "$FPR" | head -3
```

**Tick "Save in Keychain" in that dialog.** That is the whole "transparent and
automatic" story: the passphrase moves into your login keychain and you stop
being asked per message. Nothing in the app changes, and the private key stays
in GnuPG.

Optionally lengthen the agent's cache so it does not re-prompt during a session:

```bash
printf 'default-cache-ttl 3600\nmax-cache-ttl 28800\n' >> ~/.gnupg/gpg-agent.conf
gpgconf --kill gpg-agent
```

## 5. Build, sign and install

```bash
./build.sh
```

It picks a Developer ID certificate if you have one and falls back to automatic
Apple Development signing otherwise — either is fine for a Mac you build on
yourself. It installs to `/Applications/MailGPG.app`, writes the LaunchAgent
plist and boots it.

If Xcode complains about the app group `group.net.pyxzl.mailgpg`, that group has
to exist on your account. Easiest fix is to open `MailGPG.xcodeproj`, select
each target's Signing & Capabilities tab with your team selected, and let Xcode
register it, then re-run `./build.sh`.

## 6. Enable it in Mail

```bash
osascript -e 'quit app "Mail"'
open -a Mail
```

Then Mail → Settings → Extensions → tick **MailGPG**.

## 7. If MailGPG does not appear in the Extensions list

This is the one open upstream bug that could sink the whole plan on Tahoe.
Collect evidence before concluding anything:

```bash
# Is the host app actually running?
launchctl print gui/$UID/net.pyxzl.mailgpg | grep -E 'state|pid'

# Does the system see the Mail extension at all?
pluginkit -m -v -p com.apple.mail.plugin.MEExtension | grep -i mailgpg

# Force a re-scan
pluginkit -a /Applications/MailGPG.app/Contents/PlugIns/MailGPGExtension.appex

# What Mail says when you open the Extensions pane
log stream --predicate 'process == "Mail"' --level debug | grep -i -E 'mailgpg|extension'
```

## 8. Verify it actually works

Round-trip through GPG itself first, so you know the keyring is sound before
blaming the extension:

```bash
echo "round trip" | gpg --encrypt --armor --recipient "$FPR" | gpg --decrypt
```

Then in Mail: send yourself a signed message, and separately a signed and
encrypted one. Check the signature verifies in a second client — Thunderbird or
Proton — since interoperating with other people's clients is the entire point.

Confirm the XPC hardening took effect (the team ID must appear, and it must be
yours):

```bash
codesign -dv --verbose=4 /Applications/MailGPG.app 2>&1 | grep TeamIdentifier
```

## 9. Watch the logs while testing

```bash
log stream --predicate 'subsystem == "net.pyxzl.mailgpg"' --level debug
```

---

## What I changed, and what I deliberately did not

Commit `894213b` is the rebrand: bundle IDs, app group, Mach service, logger
subsystems, `DEVELOPMENT_TEAM`.

Commit `349cda3` is four fixes:

**XPC gate** (`MailGPG/GPGServiceListener.swift`) — the client requirement was
`identifier "..."` alone, which any ad-hoc signed binary can satisfy, making the
host app a signing and decryption oracle for any local process. Now pinned to
`anchor apple generic` and your team's leaf certificate.

**Signer selection** (`MailGPGExtension/MessageSecurityHandler.swift`) — the
From address was compared as `"Ravi <ravi@…>"` against a key's bare email, so it
never matched with a display name present and fell through to "first key in the
keyring". Now uses the existing `bareAddress` helper, and signing requires an
exact match instead of falling back.

**Keyserver defaults** (`MailGPGExtension/GPGService.swift`) — dropped
`keyserver.ubuntu.com`. SKS-lineage servers accept unverified uploads, so a
stranger can publish a key bearing your correspondent's address and have it
auto-imported and used.

**Recipient row** (`MailGPGExtension/ComposeSecurityView.swift`) — shows the key
ID and whether the key is verified, instead of a green "Key found" that looked
identical for a key you checked in person and one fetched off a keyserver two
seconds ago.

All seven findings from the review are now fixed. The remaining four:

**Status parsing** (`GPGServiceImpl.swift`) — `decrypt` tested stderr for
`[GNUPG:] DECRYPTION_OKAY` and `verify` concatenated stdout and stderr before
looking for `GOODSIG`. GPG's human-readable output echoes user ID strings,
which are chosen by whoever made the key, so a crafted UID could forge a
verdict. `gpgWithStatus()` now writes status to a private 0600 file and parses
only that. The human-readable fallback is gone.

**Signer identity** (`MessageSecurityHandler.swift`) — a valid signature from
any key rendered as signed, with no check that the signing key belongs to the
From address. Mismatches are now reported as an invalid signature naming both
addresses. Encryption status is unaffected.

**BCC disclosure** (XPC protocol, `GPGServiceImpl.swift`) — every recipient
fingerprint became a `--recipient`, and OpenPGP stamps a readable key ID per
recipient into the packet, so the To line learned who was blind-copied. BCC
addresses now go through `--hidden-recipient`.

**Protected subjects** (`GPGServiceImpl+MIME.swift`) — the Subject can now
travel inside the encrypted entity, with the outer one replaced by the `...`
placeholder the decode path already recognised. **Off by default**, with a
"Hide subject line" toggle in the compose panel: recipients whose client does
not implement protected headers see `...` and no explanation.

## Later round: performance, trust enforcement, Autocrypt

**Detection before hashing** — the content-hash cache key made every plaintext
message Mail indexed pay a full SHA-256, and the negative cache that avoided a
rescan grew without bound. Detection now runs first, so only PGP messages are
hashed or cached, and the decode cache is capped at 24 entries because it holds
decrypted plaintext.

**No more `gpg --card-status` per send** — both sign paths spawned it and used
only the exit code, for a log line. With no smartcard present it starts scdaemon
and can block for seconds. Smartcard keys still resolve when GPG needs them.

**Revoked and expired signing keys** — GPG emits `REVKEYSIG` / `EXPKEYSIG`
instead of `GOODSIG`, and neither parser knew them, so both reported the generic
"no valid signature". A revoked key now says so.

**Recipient key pinning** — the fingerprint used for each address is remembered,
and a different key for a known address blocks the send naming both key IDs.
Marking the new key verified in Manage Keys accepts and re-pins it. This is not
GnuPG's `--trust-model tofu`: in batch mode a TOFU conflict fails the encrypt
without naming a recipient, and first contact fails too unless the default
policy is loosened to the point of pointlessness.

**Autocrypt** (off by default, toggle in the compose panel) — outgoing mail
carries your public key in an `Autocrypt` header, and keys are harvested from
incoming mail whose `addr` matches the From address. Key exchange then happens
through the correspondence rather than a keyserver you have to trust. Harvested
keys are still subject to pinning, so a later substitution is still caught.

To exercise Autocrypt, turn it on, mail yourself from an account whose key the
Mac does not hold, and watch:

```bash
log stream --predicate 'subsystem == "net.pyxzl.mailgpg"' --level debug | grep autocrypt
```

You want `header prepared` on the way out and `imported key` on the way in. If
the outgoing header never appears, check the raw source of a sent message for an
`Autocrypt:` line — a very long unfolded header is the most likely thing for
Mail to mangle, and folding it is the first thing to try.

## Known gap: a failed decryption explains nothing

When decryption fails — you do not hold the key, the ciphertext is damaged —
`decodedMessage` returns nil and Mail renders the raw MIME. The user sees an
armoured block and no explanation.

`SecurityStatus.decryptionFailed` exists for exactly this and is never
produced. The reason is a comment left by the original author: returning an
`MEDecodedMessage` carrying the original encrypted data makes Mail's indexer
loop and trip a KVO re-entrancy crash. Given that Mail has already crashed once
during this work, that is not a claim worth testing casually.

A safer route probably exists — returning decoded data that is a short
explanation rather than the original ciphertext, so the indexer sees something
new — but it needs deliberate testing against a mailbox you do not mind
breaking, not a live one.

## A MailKit limit worth knowing

`MEMessageActionHandler` — the hook that sees plaintext mail — is invoked only
for messages delivered to the **Inbox**, only at download time, and never
retroactively. Mail that this same Mail instance sent, that the server files
into another mailbox, or that arrived before the extension was installed is
never offered to it. Two developers report the same on Apple's forums, and it
matches what the logs here show: for self-addressed mail Mail does not even ask
for the handler.

This bounds Autocrypt harvesting, which is fine — keys from mail people send you
is exactly the intended scope. It also killed an attempt to tint PGP mail in the
message list: the colouring worked only through this hook, so it could never
have coloured a Sent copy or anything already downloaded. The feature was
removed rather than shipped as something that appears broken.

It also means testing anything on this path requires a message from outside —
sending to yourself from the same Mail instance produces no Inbox delivery and
no handler call.

## When PGP is offered at all

Signing and encryption used to be offered on every message the moment the host
app was running. That is how a signed message reaches someone whose client
renders it as a cryptic attachment, and how mail gets encrypted to a key its
owner abandoned years ago.

An extension cannot turn the padlock on — `MEOutgoingMessageEncodingStatus`
reports capability and `composeContext.shouldEncrypt` is read-only — but it can
withhold the option. Signing is now offered only to addresses with evidence of
PGP use, and encryption only when they also have a usable key.

Evidence is use, not publication: mail they sent carrying PGP or an Autocrypt
header, mail you successfully encrypted to them before, or a key you verified
yourself in Manage Keys. A published key on its own proves nothing — anyone can
publish one, and a forgotten ten-year-old key looks exactly like a live one.

To start with someone who has never written to you, verify their key in Manage
Keys. To turn the whole policy off, untick "Only offer PGP to known
correspondents" in the compose panel.

Worth an experiment once this is running: address a message to someone with
evidence and a key, and see whether Mail enables the sign and encrypt buttons on
its own. It does exactly that for S/MIME when a certificate is available. If it
behaves the same way for MailKit extensions, this policy delivers automatic
encryption for the people it should apply to, without the extension ever
choosing it.

## Testing the four

Signer mismatch is the one worth exercising deliberately, since it changes what
you see on legitimate mail if an address is missing from a key. Send yourself a
signed message from each account and confirm both still verify. If one now
reports an invalid signature, the signing key lacks that address as a UID — add
it with `gpg --edit-key <fpr>` then `adduid`, rather than reverting the check.

For BCC, send an encrypted message to one address with another in BCC, then
inspect the packet from the recipient's side:

```bash
gpg --list-packets < message.asc | grep -A1 "pubkey enc packet"
```

The blind recipient should appear as keyid `0000000000000000`.

For protected subjects, turn the toggle on, send to yourself, and confirm the
outer subject reads `...` in the raw source while Mail displays the real one in
a banner.
