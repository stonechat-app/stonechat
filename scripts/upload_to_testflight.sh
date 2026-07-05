#!/bin/bash

# Zeon Chat - TestFlight Upload Script
# Validates and uploads the IPA to App Store Connect

set -e

echo "Starting TestFlight Upload..."

# Change to the repo root directory
cd "$(dirname "$0")/.."

# Load environment variables from .env.appstore if it exists
if [ -f ".env.appstore" ]; then
    echo "Loading credentials from .env.appstore..."
    export $(grep -v '^#' .env.appstore | grep -v '^$' | xargs)
fi

# Find the IPA file automatically
IPA_FILE=$(find app/build/ios/ipa -name "*.ipa" 2>/dev/null | head -1)

if [ -z "$IPA_FILE" ]; then
    echo "Error: No IPA file found in app/build/ios/ipa/"
    echo "Run first: ./scripts/build_ios.sh"
    exit 1
fi

echo "Found IPA: $IPA_FILE"

# Derive credentials directory from API_KEY_PATH
API_PRIVATE_KEYS_DIR=$(dirname "${API_KEY_PATH:-credentials/AuthKey.p8}")
API_KEY_ID="${API_KEY_ID:-}"
API_ISSUER_ID="${API_ISSUER_ID:-}"

# Check xcrun
if ! command -v xcrun &> /dev/null; then
    echo "Error: xcrun not found. Install Xcode Command Line Tools:"
    echo "  xcode-select --install"
    exit 1
fi

# Validate credentials
if [ -z "$API_KEY_ID" ] || [ -z "$API_ISSUER_ID" ]; then
    echo "Error: API_KEY_ID and API_ISSUER_ID must be set in .env.appstore"
    exit 1
fi

API_KEY_FILE="$API_PRIVATE_KEYS_DIR/AuthKey_${API_KEY_ID}.p8"
if [ ! -f "$API_KEY_FILE" ]; then
    echo "Error: API Key file not found at: $API_KEY_FILE"
    exit 1
fi

echo "Using API Key: $API_KEY_ID"
echo ""

# Step 1: Validate
echo "Step 1/2: Validating IPA..."
API_PRIVATE_KEYS_DIR="$API_PRIVATE_KEYS_DIR" \
xcrun altool --validate-app \
    -f "$IPA_FILE" \
    -t ios \
    --apiKey "$API_KEY_ID" \
    --apiIssuer "$API_ISSUER_ID"

echo "Validation passed!"
echo ""

# Step 2: Upload
echo "Step 2/2: Uploading to App Store Connect..."
echo "This may take several minutes..."
echo ""

API_PRIVATE_KEYS_DIR="$API_PRIVATE_KEYS_DIR" \
xcrun altool --upload-app \
    -f "$IPA_FILE" \
    -t ios \
    --apiKey "$API_KEY_ID" \
    --apiIssuer "$API_ISSUER_ID"

echo ""
echo "Upload completed successfully!"
echo ""
echo "Next steps:"
echo "  1. Go to https://appstoreconnect.apple.com → TestFlight"
echo "  2. Wait 5-15 minutes for processing"
echo "  3. Distribute to internal testers"
