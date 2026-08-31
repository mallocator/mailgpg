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

Three findings from the review are **not** fixed here, because each needs
changes I could not compile-check:

- Status parsing reads `[GNUPG:]` lines out of stderr, which also carries
  attacker-chosen UID text. The fix is a dedicated status fd, which means
  changing the `gpg()` subprocess helper.
- BCC recipients are disclosed to everyone via their key IDs. The fix needs a
  separate hidden-recipient list threaded through the XPC protocol.
- Subject lines are never encrypted on send, though the decode path already
  understands protected headers.

Once you have a green build, those are the next three commits.
