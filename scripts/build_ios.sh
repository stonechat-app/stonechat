#!/bin/bash

# Stonechat - iOS Production Build Script
# Increments the build number and builds the production IPA

set -e

echo "Starting iOS Production Build..."

# Change to the Flutter app directory
cd "$(dirname "$0")/../app"

# Check if Flutter is installed
if ! command -v flutter &> /dev/null; then
    echo "Error: Flutter is not installed or not in PATH"
    exit 1
fi

echo "Flutter version:"
flutter --version
echo ""

# Increment build number in pubspec.yaml
echo "Incrementing build number..."
PUBSPEC_FILE="pubspec.yaml"

CURRENT_VERSION=$(grep '^version:' "$PUBSPEC_FILE" | sed 's/version: //')
VERSION_NAME=$(echo "$CURRENT_VERSION" | cut -d'+' -f1)
BUILD_NUMBER=$(echo "$CURRENT_VERSION" | cut -d'+' -f2)

NEW_BUILD_NUMBER=$((BUILD_NUMBER + 1))
NEW_VERSION="${VERSION_NAME}+${NEW_BUILD_NUMBER}"

echo "  Current: $CURRENT_VERSION"
echo "  New:     $NEW_VERSION"

sed -i.bak "s/^version: .*/version: $NEW_VERSION/" "$PUBSPEC_FILE"
rm "${PUBSPEC_FILE}.bak"

echo "Build number incremented to $NEW_BUILD_NUMBER"
echo ""

# Bake the backend coordinates into the build. The hosted hub is live at
# https://hub.stonechat.app (Caddy/Let's Encrypt in front of the hub VM);
# override STONECHAT_HUB only to build against a different deployment.
STONECHAT_HUB="${STONECHAT_HUB:-https://hub.stonechat.app}"

# No provider is baked by default: the app picks it from the account's plan
# (mailbox → mailbox_host, machine → gcp). A baked STONECHAT_PROVIDER overrides
# the plan mapping in every install of the build — set it only for test builds.
DEFINES=(--dart-define=STONECHAT_HUB="$STONECHAT_HUB")
if [ -n "${STONECHAT_PROVIDER:-}" ]; then
    DEFINES+=(--dart-define=STONECHAT_PROVIDER="$STONECHAT_PROVIDER")
fi

# Build the iOS app
echo "Building iOS app (STONECHAT_HUB=$STONECHAT_HUB, STONECHAT_PROVIDER=${STONECHAT_PROVIDER:-<plan-driven>})..."
flutter build ipa "${DEFINES[@]}"

# Find the generated IPA (name may vary)
IPA_FILE=$(find build/ios/ipa -name "*.ipa" 2>/dev/null | head -1)

if [ -z "$IPA_FILE" ]; then
    echo "Error: No IPA file found in app/build/ios/ipa/"
    exit 1
fi

# `flutter build ipa` exits 0 even when it archives fine but cannot EXPORT the
# IPA — missing "Apple Distribution" certificate, no Apple ID in Xcode — and
# prints "Try distributing the app in Xcode" instead. An old IPA left in
# build/ios/ipa from a previous release then satisfies the check above, and this
# script would announce the new version while pointing at the old binary. That
# is how a build with a retired provider name nearly went to TestFlight.
#
# So trust the IPA's own build number, not its presence.
IPA_PLIST=$(mktemp -t stonechat-ipa-plist)
trap 'rm -f "$IPA_PLIST"' EXIT
unzip -p "$IPA_FILE" 'Payload/*.app/Info.plist' > "$IPA_PLIST" 2>/dev/null || true
IPA_BUILD=$(plutil -extract CFBundleVersion raw "$IPA_PLIST" 2>/dev/null || echo "?")

if [ "$IPA_BUILD" != "$NEW_BUILD_NUMBER" ]; then
    echo "Error: $IPA_FILE is build $IPA_BUILD, not the $NEW_BUILD_NUMBER just built." >&2
    echo "       The archive succeeded but the App Store export did not, so this is a" >&2
    echo "       stale IPA. Scroll up for the exportArchive errors — usually no" >&2
    echo "       \"Apple Distribution\" certificate for the team in Xcode." >&2
    echo "       The archive itself is fine and needs no rebuild:" >&2
    echo "         open build/ios/archive/Runner.xcarchive   # Organizer -> Distribute App" >&2
    exit 1
fi

echo ""
echo "Build completed successfully!"
echo "IPA: app/$IPA_FILE"
echo "Version: $NEW_VERSION"
