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
# (mailbox → machine_host, machine → gcp). A baked STONECHAT_PROVIDER overrides
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

echo ""
echo "Build completed successfully!"
echo "IPA: app/$IPA_FILE"
echo "Version: $NEW_VERSION"
