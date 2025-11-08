#!/bin/bash
# Generate Android launcher icons from SVG

# Check if ImageMagick is installed
if ! command -v convert &> /dev/null; then
    echo "Installing ImageMagick via Homebrew..."
    brew install imagemagick
fi

# Create Android icons directory if not exists
mkdir -p android/app/src/main/res/{mipmap-mdpi,mipmap-hdpi,mipmap-xhdpi,mipmap-xxhdpi,mipmap-xxxhdpi}

# Generate icons at different resolutions
convert -background none assets/logo.svg -resize 48x48 android/app/src/main/res/mipmap-mdpi/ic_launcher.png
convert -background none assets/logo.svg -resize 72x72 android/app/src/main/res/mipmap-hdpi/ic_launcher.png
convert -background none assets/logo.svg -resize 96x96 android/app/src/main/res/mipmap-xhdpi/ic_launcher.png
convert -background none assets/logo.svg -resize 144x144 android/app/src/main/res/mipmap-xxhdpi/ic_launcher.png
convert -background none assets/logo.svg -resize 192x192 android/app/src/main/res/mipmap-xxxhdpi/ic_launcher.png

echo "✅ App icons generated successfully!"
