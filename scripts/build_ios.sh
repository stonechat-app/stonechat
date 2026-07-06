#!/bin/bash

# Zeon Chat - iOS Production Build Script
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

# Bake the backend coordinates into the build. Without ZEON_CP a release
# build points at the hosted control plane (control.zeonchat.com), which
# doesn't exist yet — refuse rather than ship a dead app.
if [ -z "$ZEON_CP" ]; then
    echo "Error: set ZEON_CP (e.g. ZEON_CP=http://35.225.244.167:8000)"
    exit 1
fi
ZEON_PROVIDER="${ZEON_PROVIDER:-fleet}"

# Build the iOS app
echo "Building iOS app (ZEON_CP=$ZEON_CP, ZEON_PROVIDER=$ZEON_PROVIDER)..."
flutter build ipa \
    --dart-define=ZEON_CP="$ZEON_CP" \
    --dart-define=ZEON_PROVIDER="$ZEON_PROVIDER"

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
