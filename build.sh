#!/usr/bin/env bash
# Build, sign and install the MailGPG fork under net.pyxzl / team 3HKD37M482.
# Run from the repo root:  ./build.sh
set -euo pipefail

TEAM_ID="3HKD37M482"
APP_BUNDLE_ID="net.pyxzl.MailGPG"
LAUNCH_LABEL="net.pyxzl.mailgpg"
MACH_SERVICE="net.pyxzl.mailgpg.gpgservice"
APP_PATH="/Applications/MailGPG.app"
PLIST="$HOME/Library/LaunchAgents/${LAUNCH_LABEL}.plist"
DERIVED="$(mktemp -d)"

say() { printf '\n\033[1m==> %s\033[0m\n' "$1"; }

say "Checking prerequisites"
command -v xcodebuild >/dev/null || { echo "Xcode not installed"; exit 1; }
command -v gpg        >/dev/null || { echo "Run: brew install gnupg pinentry-mac"; exit 1; }
xcodebuild -version
gpg --version | head -1

say "Available signing identities"
security find-identity -v -p codesigning || true

# Prefer a Developer ID cert if you have one (needed only if you ever want to
# hand the build to another machine); otherwise Apple Development is fine for
# a Mac you build on yourself.
if security find-identity -v -p codesigning | grep -q "Developer ID Application"; then
  SIGN_ARGS=(-configuration Release CODE_SIGN_STYLE=Manual \
             CODE_SIGN_IDENTITY="Developer ID Application")
  echo "Using: Developer ID Application"
else
  # The Release config pins Developer ID provisioning profiles, which conflict
  # with automatic signing. Clear them explicitly — an empty specifier is what
  # tells Xcode "let automatic signing choose".
  SIGN_ARGS=(-configuration Release CODE_SIGN_STYLE=Automatic \
             PROVISIONING_PROFILE_SPECIFIER="" \
             PROVISIONING_PROFILE="" \
             CODE_SIGN_IDENTITY="Apple Development")
  echo "Using: automatic signing (Apple Development)"
fi

say "Building"
BUILD_LOG="$DERIVED/build.log"
set +e
xcodebuild \
  -project MailGPG.xcodeproj \
  -scheme MailGPG \
  -derivedDataPath "$DERIVED" \
  -destination 'platform=macOS' \
  DEVELOPMENT_TEAM="$TEAM_ID" \
  "${SIGN_ARGS[@]}" \
  -allowProvisioningUpdates \
  build > "$BUILD_LOG" 2>&1
BUILD_STATUS=$?
set -e

if [ $BUILD_STATUS -ne 0 ]; then
  echo
  echo "Build failed. Diagnostics:"
  echo "------------------------------------------------------------"
  # xcodebuild prints the useful lines as path:line:col: error: message,
  # then repeats a wall of command lines at the end. Show only the former.
  grep -E "^/.*:[0-9]+:[0-9]+: (error|warning):" "$BUILD_LOG" | sort -u | head -60
  echo "------------------------------------------------------------"
  echo "Full log kept at: $BUILD_LOG"
  echo "(that directory is not cleaned up on failure)"
  exit 1
fi

BUILT="$DERIVED/Build/Products/Release/MailGPG.app"
[ -d "$BUILT" ] || { echo "Build produced no app at $BUILT"; exit 1; }

say "Verifying signature and entitlements"
codesign -dv --verbose=4 "$BUILT" 2>&1 | grep -E "Identifier|TeamIdentifier|Authority" || true

# The XPC gate in GPGServiceListener.swift pins the caller's team ID. If the
# certificate that actually signed this build belongs to a different team, the
# extension will be refused by the host app and every GPG operation fails with
# a confusing "host app not running". Catch that here rather than in Mail.
ACTUAL_TEAM=$(codesign -dv --verbose=4 "$BUILT" 2>&1 | awk -F= '/^TeamIdentifier/{print $2}')
PINNED_TEAM=$(grep -o 'subject.OU\] = "[A-Z0-9]*"' MailGPG/GPGServiceListener.swift | grep -o '"[A-Z0-9]*"' | tr -d '"')
if [ -n "$ACTUAL_TEAM" ] && [ "$ACTUAL_TEAM" != "$PINNED_TEAM" ]; then
  echo
  echo "ERROR: signed by team '$ACTUAL_TEAM' but GPGServiceListener.swift pins '$PINNED_TEAM'."
  echo "The extension would be refused by the host app. Fix it with:"
  echo
  echo "  sed -i '' 's/$PINNED_TEAM/$ACTUAL_TEAM/' MailGPG/GPGServiceListener.swift"
  echo "  ./build.sh"
  echo
  exit 1
fi
echo "Team ID check: signed by $ACTUAL_TEAM, pinned $PINNED_TEAM — match"
codesign -d --entitlements - "$BUILT" 2>/dev/null | head -20 || true

say "Installing to $APP_PATH"
launchctl bootout "gui/$UID/$LAUNCH_LABEL" 2>/dev/null || true
rm -rf "$APP_PATH"
cp -R "$BUILT" "$APP_PATH"

say "Registering the login agent"
mkdir -p "$HOME/Library/LaunchAgents"
cat > "$PLIST" <<PLISTEOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>${LAUNCH_LABEL}</string>
  <key>AssociatedBundleIdentifiers</key>
  <string>${APP_BUNDLE_ID}</string>
  <key>ProgramArguments</key>
  <array>
    <string>${APP_PATH}/Contents/MacOS/MailGPG</string>
  </array>
  <key>KeepAlive</key>
  <true/>
  <key>MachServices</key>
  <dict>
    <key>${MACH_SERVICE}</key>
    <true/>
  </dict>
</dict>
</plist>
PLISTEOF

launchctl bootstrap "gui/$UID" "$PLIST"
sleep 2
launchctl print "gui/$UID/$LAUNCH_LABEL" | grep -E "state|pid" || true

rm -rf "$DERIVED"

say "Done"
cat <<'NEXT'
Now, in this order:

  1. Quit Mail completely:            osascript -e 'quit app "Mail"'
  2. Open Mail, then Mail > Settings > Extensions and tick MailGPG.
  3. Open a new compose window and check the MailGPG panel appears.

If MailGPG does not show up in the Extensions list, see SETUP.md, step 7.
NEXT
