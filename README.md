# MailGPG

OpenPGP for Apple Mail on macOS. Sign, encrypt, decrypt and verify mail using
the GnuPG keyring you already have — no subscription, no support plan.

This is a fork of [mahaupt/mailgpg](https://github.com/mahaupt/mailgpg) with a
set of security and correctness fixes on top. [What's different](#whats-different-in-this-fork)
lists them.

---

## Requirements

| | |
|---|---|
| macOS | 14 Sonoma or later (developed and used on 26 Tahoe) |
| Mail | Apple Mail — this is a MailKit extension, so it works nowhere else |
| GnuPG | `brew install gnupg` |
| pinentry-mac | `brew install pinentry-mac` — required, see [Passphrases](#passphrases) |

Apple Mail on iOS has no MailKit extension support, so this is macOS only.

## Install

```bash
brew install --cask mallocator/mailgpg/mailgpg
```

The cask installs the app, pulls in GnuPG and pinentry-mac, and registers the
background helper as a login item.

To build it yourself instead, see [SETUP.md](SETUP.md) — it needs Xcode and an
Apple Developer account, and `./build.sh` does the rest.

Then enable it: **Mail → Settings → Extensions → MailGPG**. Quit Mail first if
it was already running, or it won't see the newly installed extension.

## Getting your key in

MailGPG reads whatever is in your GnuPG keyring, so any key GnuPG can see will
work. If you already use `gpg` on this Mac, you're done.

Coming from a phone: OpenKeychain's **Backup** produces an encrypted
`.sec.pgp` that `gpg --import` cannot read directly — decrypt it first with the
32-character backup code, or use the per-key export, which gives a plain `.asc`.

```bash
gpg --import secret.asc                      # or: gpg --decrypt backup.sec.pgp | gpg --import
gpg --list-secret-keys --keyid-format=long   # note the 40-char fingerprint

FPR=<paste the fingerprint>
echo "${FPR}:6:" | gpg --import-ownertrust    # your own key is ultimately trusted
gpg --check-trustdb
```

Creating a key from scratch: [GitHub's guide](https://docs.github.com/en/authentication/managing-commit-signature-verification/generating-a-new-gpg-key)
covers it well.

### Passphrases

The helper runs in the background with no terminal, so GnuPG's default
text-mode passphrase prompt can never appear — signing and decryption fail
silently without a graphical one. Set it once:

```bash
echo "pinentry-program $(brew --prefix)/bin/pinentry-mac" >> ~/.gnupg/gpg-agent.conf
gpgconf --kill gpg-agent
```

The compose panel's **Diagnostics** screen detects a missing or wrong setting
and offers a one-click fix if you'd rather not edit the file.

Then sign something once to trigger the prompt, and **tick "Save in Keychain"**
in the dialog. Your passphrase moves into the login keychain and you stop being
asked per message — which is the difference between this being pleasant and
being tedious. With two keys, do it once per key.

```bash
echo test | gpg --clearsign --local-user "$FPR" | head -3
```

## When PGP is offered

Mail decides whether the sign and encrypt buttons start switched on from what
the extension reports it *can* do. MailKit gives an extension no way to set
those toggles directly, so what it can do is decline to offer them — and that
is how this fork keeps signed mail away from people whose client would show it
as a cryptic attachment.

Signing and encryption are offered only to addresses with **evidence of PGP
use**:

- they sent you mail carrying PGP, or an Autocrypt header
- they publish a key through Web Key Directory
- you have successfully encrypted to them before
- you verified their key yourself in Manage Keys

A key sitting on a keyserver is deliberately *not* evidence. Anyone can upload
one, nothing ever expires off, and a key its owner abandoned a decade ago looks
identical to one in daily use.

Encryption additionally needs a usable key for every recipient. To start
writing to someone who has never written to you, verify their key in **Manage
Keys**. To switch the whole policy off, untick **Only offer PGP to known
correspondents** in the compose panel.

## Options

All three live in the compose panel and are off, or conservative, by default.

**Only offer PGP to known correspondents** — the policy above. On by default.

**Attach my key (Autocrypt)** — adds your public key to outgoing mail as an
`Autocrypt` header and harvests correspondents' keys from mail they send you,
so key exchange happens through the correspondence rather than a keyserver you
have to trust. Interoperates with Thunderbird, K-9 and Delta Chat.

**Hide subject line** — moves the Subject inside the encrypted part, leaving
`...` visible. Off by default: recipients whose client doesn't implement
protected headers see the placeholder and no explanation.

## Troubleshooting

**MailGPG isn't in Mail's extension list.** Quit Mail completely and reopen it.
If it still doesn't appear:

```bash
launchctl print gui/$UID/net.pyxzl.mailgpg | grep -E 'state|pid'
pluginkit -m -v -p com.apple.mail.plugin.MEExtension | grep -i mailgpg
```

**Signing or decryption does nothing.** Almost always pinentry. Check
Diagnostics in the compose panel.

**"No secret key found for <address>."** Deliberate — the key that signs must
carry the From address as a user ID, rather than the extension silently signing
with whatever key came first. Add the address:

```bash
gpg --edit-key <fingerprint>
# adduid → enter name and address → save
```

**"The public key for these recipients is not the one used before."** The key
for that address changed since you last wrote to them. That is what key
substitution looks like, so confirm the new fingerprint with the person through
another channel, then mark it verified in Manage Keys to accept it.

**Watching what it's doing:**

```bash
log stream --predicate 'subsystem == "net.pyxzl.mailgpg"' --level debug
```

## What's different in this fork

Security fixes: the XPC gate is pinned to the signing team, so a local process
can no longer claim the extension's bundle identifier and use the helper as a
signing and decryption oracle; GPG status is parsed from a private file rather
than stderr, which carries attacker-chosen user IDs; recipient keys are pinned
on first use so a substituted key stops the send; signatures whose key doesn't
match the From address are reported as invalid; revoked and expired signing
keys say so instead of reading as "no signature"; BCC recipients are encrypted
to as hidden recipients rather than being disclosed to everyone.

Correctness fixes: the decode cache is keyed on message content rather than on
headers two messages can share — which made Mail render one message's plaintext
in place of another's; the signing key is chosen by the From address and, where
several keys carry it, the newest.

New: Autocrypt, protected subject lines, and the offer policy described above.

Performance: PGP detection runs before hashing so plaintext mail costs almost
nothing, the decode cache is bounded, and `gpg --card-status` no longer runs on
every send.

Full detail, including what is still open, is in [SETUP.md](SETUP.md).

## Architecture

MailKit extensions are sandboxed and a sandboxed process cannot spawn `gpg`, so
there are two processes:

- **`MailGPG.app`** — unsandboxed background helper, runs GPG, exposes results
  over XPC. Started at login by the launch agent the cask installs.
- **`MailGPGExtension`** — the sandboxed MailKit extension Mail loads. All UI,
  no crypto; everything goes through XPC.

The helper accepts XPC connections only from a binary signed by the same team,
and never handles your private key or passphrase — gpg-agent does.

## Releasing

The pipeline in `.github/workflows/release.yml` builds, signs with Developer ID,
notarizes, staples, publishes a GitHub release and updates the Homebrew tap.
Push a tag:

```bash
git tag v1.0.0 && git push origin v1.0.0
```

It needs a Developer ID Application certificate (an Apple Development
certificate signs local builds but cannot be distributed), an app-specific
password for notarization, and the tap repository. Setup is in
[`.github/workflows/SECRETS.md`](.github/workflows/SECRETS.md).

## License

GPL-3.0, as upstream. Original work by [Marcel Haupt](https://github.com/mahaupt).
