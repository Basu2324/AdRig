#!/usr/bin/env python3
"""AdRig Logo Generator - Simple, Clean, Professional"""

from PIL import Image, ImageDraw, ImageFont, ImageFilter
import os
import math

def create_adrig_text_logo(size=1024):
    """Create simple, professional AdRig text logo"""
    img = Image.new('RGBA', (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    
    cx, cy = size // 2, size // 2
    
    # Bold font
    font_size = int(size * 0.42)
    try:
        font_paths = [
            '/System/Library/Fonts/Supplemental/Arial Bold.ttf',
            '/System/Library/Fonts/SFNS.ttf',
            '/Library/Fonts/Arial Bold.ttf',
            '/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf',
        ]
        font = None
        for path in font_paths:
            if os.path.exists(path):
                font = ImageFont.truetype(path, font_size)
                break
        if font is None:
            font = ImageFont.load_default()
    except:
        font = ImageFont.load_default()
    
    text = "AdRig"
    
    # Get text bbox
    bbox = draw.textbbox((0, 0), text, font=font)
    text_width = bbox[2] - bbox[0]
    text_height = bbox[3] - bbox[1]
    
    # Center position
    x = cx - text_width // 2
    y = cy - text_height // 2
    
    # Simple clean rendering
    
    # Soft glow
    for i in range(15, 0, -1):
        opacity = int(40 * (1 - i / 15))
        draw.text((x, y), text, font=font, fill=(0, 217, 255, opacity))
    
    # Simple shadow
    draw.text((x + 3, y + 4), text, font=font, fill=(0, 0, 0, 100))
    
    # Gradient simulation (3 layers)
    draw.text((x, y + 2), text, font=font, fill=(0, 102, 255, 255))  # Deep blue
    draw.text((x, y + 1), text, font=font, fill=(0, 160, 255, 255))  # Mid blue
    draw.text((x, y), text, font=font, fill=(0, 217, 255, 255))      # Bright cyan
    
    return img

def main():
    print("🚀 Generating Simple AdRig Logo...")
    
    icon = create_adrig_text_logo(1024)
    icon.save('assets/icon/adrig_icon.png')
    print("✓ adrig_icon.png (1024x1024)")
    
    fg = create_adrig_text_logo(432)
    fg.save('assets/icon/adrig_icon_foreground.png')
    print("✓ adrig_icon_foreground.png (432x432)")
    
    for s in [16, 32, 48, 64, 128, 256, 512]:
        icon.resize((s, s), Image.Resampling.LANCZOS).save(f'assets/icon/adrig_icon_{s}.png')
        print(f"✓ adrig_icon_{s}.png")
    
    print("\n✨ Simple AdRig Logo Complete!")
    print("   Clean, professional branding")

if __name__ == "__main__":
    main()
