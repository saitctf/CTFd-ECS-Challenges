#!/bin/bash
# Script to get the latest CTFd migration revision from GitHub

echo "Fetching latest CTFd migration revision from GitHub..."
echo ""

# Clone CTFd repo to temp directory
TMP_DIR=$(mktemp -d)
cd "$TMP_DIR"

# Clone the migrations/versions directory
echo "Cloning CTFd repository..."
git clone --depth 1 --filter=blob:none --sparse https://github.com/CTFd/CTFd.git > /dev/null 2>&1
cd CTFd

# Checkout just the migrations/versions directory
git sparse-checkout init --cone > /dev/null 2>&1
git sparse-checkout set migrations/versions > /dev/null 2>&1

# Find the latest migration file
LATEST_FILE=$(ls -t migrations/versions/*.py 2>/dev/null | head -1)

if [ -z "$LATEST_FILE" ]; then
    echo "ERROR: Could not find migration files"
    exit 1
fi

# Extract revision from the file
REVISION=$(grep "^revision" "$LATEST_FILE" | head -1 | sed "s/revision = //" | sed "s/['\"]//g" | tr -d ' ')

if [ -z "$REVISION" ]; then
    echo "ERROR: Could not extract revision from $LATEST_FILE"
    exit 1
fi

echo "Latest migration file: $(basename $LATEST_FILE)"
echo ""
echo "Latest revision: $REVISION"
echo ""
echo "Run this SQL command in your database:"
echo "INSERT INTO alembic_version (version_num) VALUES ('$REVISION');"
echo ""

# Cleanup
cd /
rm -rf "$TMP_DIR"

