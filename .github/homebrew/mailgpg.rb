# This file is the initial template for the mallocator/homebrew-mailgpg tap.
# Copy it to: mallocator/homebrew-mailgpg/Casks/mailgpg.rb
# Version and sha256 are updated automatically by the release GitHub Action.

cask "mailgpg" do
  version "1.0.0"
  sha256 "placeholder_updated_by_ci"

  url "https://github.com/mallocator/mailgpg/releases/download/v#{version}/MailGPG-#{version}.dmg"
  name "MailGPG"
  desc "Mail extension for GPG email encryption and signing"
  homepage "https://github.com/mallocator/mailgpg"

  # GPG binary and GUI-compatible pinentry are required for all operations
  depends_on formula: "gnupg"
  depends_on formula: "pinentry-mac"
  depends_on macos: :sonoma

  app "MailGPG.app"

  # MailGPG.app registers its helper with launchd itself when it is opened.
  # `launchctl` stops the helper, also on upgrade, and deletes the
  # ~/Library/LaunchAgents plist older versions of this cask wrote; it runs
  # outside Homebrew's sandbox. `quit` closes an open status window, which
  # an upgrade reopens, registering the new helper.
  uninstall launchctl: "net.pyxzl.mailgpg",
            quit:      "net.pyxzl.MailGPG"

  zap trash: [
    "~/Library/Containers/net.pyxzl.MailGPG.MailGPGExtension",
    "~/Library/Group Containers/group.net.pyxzl.mailgpg",
    "~/Library/Preferences/net.pyxzl.MailGPG.plist",
    "~/Library/Saved Application State/net.pyxzl.MailGPG.savedState",
  ]

  caveats <<~EOS
    Open MailGPG.app once after every install or upgrade: it starts the
    helper and registers it as a login item.
      open /Applications/MailGPG.app

    To finish setup, enable the Mail extension:
      Mail → Settings → Extensions → MailGPG ✓

    Restart Mail if it was already open.
  EOS
end
