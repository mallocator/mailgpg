# mailgpg: agent instructions

The owner's fork of mahaupt/mailgpg: OpenPGP for Apple Mail as a MailKit extension plus a host app that talks to
GnuPG over XPC. README.md lists what the fork changes; SETUP.md the remaining fixes and how to test them.

## Commands
- Setup once per clone: `brew install gnupg pinentry-mac swiftlint`.
- Check (the hook runs it): `swiftlint lint --strict` from the repo root (the nested MailGPGTests config only merges
  from there).
- Full suite (CI): `xcodebuild test -project MailGPG.xcodeproj -scheme MailGPG -destination 'platform=macOS'
  CODE_SIGN_IDENTITY="" CODE_SIGNING_REQUIRED=NO CODE_SIGNING_ALLOWED=NO`.
- Build and install on the owner's Mac: `./build.sh` (`--test` runs the tests too); it signs with his team and
  replaces /Applications/MailGPG.app: only when he asks.
- Release: a `vX.Y.Z` tag builds and publishes: only with the owner's OK.

## Differences from the global standards
- Branches: work happens on `pyxzl`; `main` tracks upstream (mahaupt). CI's test workflow runs on main and pull
  requests only.
- Public repo, self-contained (owner 2026-11-09): configs (.swiftlint.yml) are copies from his standards repo.

## Rules
- Lenient UTF-8 decodes of headers and armour are deliberate; each `swiftlint:disable:next
  optional_data_string_conversion` says why. Strict decodes everywhere else.
- Known failing test: `ParsingTests.testRealGPG_decryptWithEmbeddedSignature` (parseUID returns an empty email for
  a bare-email user ID, 2026-11-10). Fix it starting from that test.
