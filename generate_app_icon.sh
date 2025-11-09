#!/bin/bash

# AdRig App Icon Generator
# This script generates app icons for Android

echo "🎨 Generating AdRig App Icons..."

# Create icon directory if not exists
mkdir -p android/app/src/main/res/mipmap-hdpi
mkdir -p android/app/src/main/res/mipmap-mdpi
mkdir -p android/app/src/main/res/mipmap-xhdpi
mkdir -p android/app/src/main/res/mipmap-xxhdpi
mkdir -p android/app/src/main/res/mipmap-xxxhdpi

# You need to:
# 1. Create a 1024x1024 PNG icon for AdRig
# 2. Use this online tool: https://icon.kitchen/
# 3. Or install flutter_launcher_icons package

echo ""
echo "📦 Installing flutter_launcher_icons..."
flutter pub add flutter_launcher_icons --dev

echo ""
echo "✅ Package installed!"
echo ""
echo "📝 Next steps:"
echo "1. Create a 1024x1024 PNG logo image"
echo "2. Save it as: assets/icon/adrig_icon.png"
echo "3. Run: flutter pub run flutter_launcher_icons"
echo ""
echo "Or use the quickstart below..."
