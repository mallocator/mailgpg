# Required GitHub Actions Secrets

Configure these at: https://github.com/mallocator/mailgpg/settings/secrets/actions

| Secret | Description | How to get it |
|--------|-------------|---------------|
| `DEVELOPER_ID_CERTIFICATE_BASE64` | Developer ID Application certificate + private key as base64-encoded .p12 | Keychain Access → export cert as .p12, then `base64 -i cert.p12 \| pbcopy` |
| `DEVELOPER_ID_CERTIFICATE_PASSWORD` | Password set when exporting the .p12 | Set when exporting from Keychain Access |
| `DEVELOPMENT_TEAM` | Your 10-character Apple Team ID | `3HKD37M482` (from Xcode project settings) |
| `APPLE_ID` | Your Apple ID email used for notarization | e.g. `you@example.com` |
| `NOTARIZATION_PASSWORD` | App-specific password for notarytool | https://appleid.apple.com → Sign-In and Security → App-Specific Passwords |
| `PROVISIONING_PROFILE_HOST_BASE64` | Developer ID provisioning profile for `net.pyxzl.MailGPG` | developer.apple.com → Profiles → + → macOS Developer ID, then `base64 -i file.provisionprofile \| pbcopy` |
| `PROVISIONING_PROFILE_EXTENSION_BASE64` | Developer ID provisioning profile for `net.pyxzl.MailGPG.MailGPGExtension` | Same as above for the extension bundle ID |
| `TAP_TOKEN` | GitHub Personal Access Token with repo write access to mallocator/homebrew-mailgpg | GitHub → Settings → Developer Settings → Personal Access Tokens (classic), scopes: `repo` |

## Triggering a release

```bash
git tag v1.0.0
git push origin v1.0.0
```

The pipeline will:
1. Build + archive with Xcode 26.6
2. Sign with Developer ID
3. Notarize + staple the app
4. Package it as a DMG, then notarize + staple the DMG
5. Create a GitHub Release with the DMG attached
6. Push the updated casks (version + SHA256) to main on mallocator/homebrew-mailgpg

## One-time setup: create the Homebrew tap repo

1. Create a new GitHub repo named `homebrew-mailgpg` under `mallocator`
2. Copy `.github/homebrew/mailgpg.rb` and `.github/homebrew/mailgpg-nodeps.rb` into `Casks/` in that repo, on its
   `main` branch (the release job pushes there and overwrites both)
3. Users can then install with: `brew install --cask mallocator/mailgpg/mailgpg` (or `.../mailgpg-nodeps`)
