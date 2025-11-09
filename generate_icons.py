#!/usr/bin/env python3
"""
AdRig Unique Brand Logo Generator
Shield with "AdRig" text and circuit DNA helix
"""

from PIL import Image, ImageDraw, ImageFont, ImageFilter
import math

def create_shield_points(center, radius):
    """Create modern shield shape points"""
    cx, cy = center
    points = []
    
    # Top
    points.append((cx, cy - radius * 1.05))
    points.append((cx - radius * 0.7, cy - radius * 0.95))
    points.append((cx - radius * 0.85, cy - radius * 0.6))
    
    # Left side
    points.append((cx - radius * 0.95, cy - radius * 0.2))
    points.append((cx - radius * 0.95, cy + radius * 0.2))
    points.append((cx - radius * 0.75, cy + radius * 0.55))
    
    # Bottom point
    points.append((cx, cy + radius * 1.12))
    
    # Right side
    points.append((cx + radius * 0.75, cy + radius * 0.55))
    points.append((cx + radius * 0.95, cy + radius * 0.2))
    points.append((cx + radius * 0.95, cy - radius * 0.2))
    
    # Top right
    points.append((cx + radius * 0.85, cy - radius * 0.6))
    points.append((cx + radius * 0.7, cy - radius * 0.95))
    
    return points

def draw_circuit_dna(draw, center, radius):
    """Draw DNA helix circuit pattern"""
    cx, cy = center
    
    # DNA double helix
    left_points = []
    right_points = []
    
    steps = 40
    for i in range(steps):
        t = i / steps
        y = cy - radius * 0.8 + (t * radius * 1.6)
        left_x = cx - radius * 0.3 * math.sin(t * math.pi * 4)
        right_x = cx + radius * 0.3 * math.sin(t * math.pi * 4)
        
        left_points.append((left_x, y))
        right_points.append((right_x, y))
    
    # Draw helix strands
    for i in range(len(left_points) - 1):
        draw.line([left_points[i], left_points[i+1]], fill=(0, 245, 255, 150), width=2)
        draw.line([right_points[i], right_points[i+1]], fill=(0, 102, 255, 150), width=2)
    
    # Connection bars
    connection_steps = 8
    for i in range(connection_steps):
        t = i / connection_steps
        y = cy - radius * 0.8 + (t * radius * 1.6)
        left_x = cx - radius * 0.3 * math.sin(t * math.pi * 4)
        right_x = cx + radius * 0.3 * math.sin(t * math.pi * 4)
        
        draw.line([(left_x, y), (right_x, y)], fill=(0, 245, 255, 80), width=2)
        draw.ellipse([left_x-2, y-2, left_x+2, y+2], fill=(0, 245, 255))
        draw.ellipse([right_x-2, y-2, right_x+2, y+2], fill=(0, 245, 255))

def draw_corner_accents(draw, center, radius):
    """Draw 4 corner targeting accents"""
    cx, cy = center
    corners = [
        (cx - radius * 0.6, cy - radius * 0.5),
        (cx + radius * 0.6, cy - radius * 0.5),
        (cx - radius * 0.5, cy + radius * 0.6),
        (cx + radius * 0.5, cy + radius * 0.6),
    ]
    
    for corner in corners:
        x, y = corner
        # Glowing dot
        draw.ellipse([x-6, y-6, x+6, y+6], fill=(0, 245, 255, 100))
        draw.ellipse([x-3, y-3, x+3, y+3], fill=(0, 245, 255))
        draw.ellipse([x-1, y-1, x+1, y+1], fill=(255, 255, 255))
        
        # Cross lines
        cross_size = 10
        draw.line([(x-cross_size, y), (x+cross_size, y)], fill=(0, 245, 255, 150), width=2)
        draw.line([(x, y-cross_size), (x, y+cross_size)], fill=(0, 245, 255, 150), width=2)

def create_adrig_icon(size=1024):
    """Create AdRig branded icon"""
    
    # Dark blue gradient background
    img = Image.new('RGBA', (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img, 'RGBA')
    
    # Radial gradient background
    center = (size // 2, size // 2)
    max_radius = math.sqrt(center[0]**2 + center[1]**2)
    
    for y in range(size):
        for x in range(size):
            distance = math.sqrt((x - center[0])**2 + (y - center[1])**2)
            ratio = distance / max_radius
            
            if ratio < 0.4:
                color = (0, 8, 32, 255)  # Deep blue
            elif ratio < 0.7:
                t = (ratio - 0.4) / 0.3
                color = (
                    int(0 + (0 - 0) * t),
                    int(8 + (24 - 8) * t),
                    int(32 + (64 - 32) * t),
                    255
                )
            else:
                t = (ratio - 0.7) / 0.3
                color = (
                    int(0 + (15 - 0) * t),
                    int(24 + (52 - 24) * t),
                    int(64 + (96 - 64) * t),
                    255
                )
            
            img.putpixel((x, y), color)
    
    draw = ImageDraw.Draw(img, 'RGBA')
    radius = int(size * 0.38)
    
    # Draw shield
    shield_points = create_shield_points(center, radius)
    draw.polygon(shield_points, fill=(0, 12, 40, 255), outline=None)
    
    # Circuit DNA helix
    draw_circuit_dna(draw, center, radius)
    
    # "AdRig" text - large and prominent
    try:
        # Try to use a bold font
        font_ad = ImageFont.truetype("/System/Library/Fonts/Helvetica.ttc", int(radius * 0.5))
        font_rig = ImageFont.truetype("/System/Library/Fonts/Helvetica.ttc", int(radius * 0.48))
    except:
        font_ad = ImageFont.load_default()
        font_rig = ImageFont.load_default()
    
    # "Ad" in top half with cyan glow
    ad_text = "Ad"
    ad_bbox = draw.textbbox((0, 0), ad_text, font=font_ad)
    ad_width = ad_bbox[2] - ad_bbox[0]
    ad_height = ad_bbox[3] - ad_bbox[1]
    ad_x = center[0] - ad_width // 2
    ad_y = center[1] - radius * 0.45
    
    # Glow effect for "Ad"
    for offset in range(8, 0, -1):
        alpha = int(40 * (1 - offset/8))
        draw.text((ad_x, ad_y), ad_text, font=font_ad, fill=(0, 245, 255, alpha))
    
    # Main "Ad" text
    draw.text((ad_x, ad_y), ad_text, font=font_ad, fill=(0, 245, 255, 255))
    
    # "Rig" in bottom half with blue-purple glow
    rig_text = "Rig"
    rig_bbox = draw.textbbox((0, 0), rig_text, font=font_rig)
    rig_width = rig_bbox[2] - rig_bbox[0]
    rig_height = rig_bbox[3] - rig_bbox[1]
    rig_x = center[0] - rig_width // 2
    rig_y = center[1] + radius * 0.05
    
    # Glow effect for "Rig"
    for offset in range(8, 0, -1):
        alpha = int(40 * (1 - offset/8))
        draw.text((rig_x, rig_y), rig_text, font=font_rig, fill=(0, 102, 255, alpha))
    
    # Main "Rig" text
    draw.text((rig_x, rig_y), rig_text, font=font_rig, fill=(0, 102, 255, 255))
    
    # Dividing line between Ad and Rig
    line_y = center[1]
    line_start = center[0] - radius * 0.4
    line_end = center[0] + radius * 0.4
    
    # Gradient line effect
    segments = 50
    for i in range(segments):
        t = i / segments
        x1 = line_start + (line_end - line_start) * t
        x2 = line_start + (line_end - line_start) * (t + 1/segments)
        
        # Fade in/out from edges
        if t < 0.2 or t > 0.8:
            alpha = int(100 * min(t/0.2, (1-t)/0.2))
        else:
            alpha = 100
        
        draw.line([(x1, line_y), (x2, line_y)], fill=(0, 245, 255, alpha), width=2)
    
    # Circuit nodes on divider
    for i in range(-2, 3):
        node_x = center[0] + (i * radius * 0.2)
        draw.ellipse([node_x-4, line_y-4, node_x+4, line_y+4], fill=(0, 245, 255, 80))
        draw.ellipse([node_x-2, line_y-2, node_x+2, line_y+2], fill=(0, 245, 255))
    
    # Corner accents
    draw_corner_accents(draw, center, radius)
    
    # Glowing border
    border_width = 3
    
    # Outer glow
    for i in range(10, 0, -1):
        alpha = int(50 * (1 - i/10))
        enlarged_points = [
            (x + (x - center[0]) * i * 0.02, y + (y - center[1]) * i * 0.02)
            for x, y in shield_points
        ]
        draw.polygon(enlarged_points, outline=(0, 245, 255, alpha), width=2)
    
    # Main border gradient
    draw.polygon(shield_points, outline=(0, 245, 255, 255), width=border_width)
    
    return img.convert('RGB')

def create_foreground_icon(size=1024):
    """Create adaptive icon foreground"""
    img = Image.new('RGBA', (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img, 'RGBA')
    
    center = (size // 2, size // 2)
    radius = int(size * 0.35)
    
    # Shield
    shield_points = create_shield_points(center, radius)
    draw.polygon(shield_points, fill=(0, 20, 60, 255))
    
    # Circuit DNA
    draw_circuit_dna(draw, center, radius)
    
    # "AdRig" text
    try:
        font_ad = ImageFont.truetype("/System/Library/Fonts/Helvetica.ttc", int(radius * 0.5))
        font_rig = ImageFont.truetype("/System/Library/Fonts/Helvetica.ttc", int(radius * 0.48))
    except:
        font_ad = ImageFont.load_default()
        font_rig = ImageFont.load_default()
    
    ad_text = "Ad"
    ad_bbox = draw.textbbox((0, 0), ad_text, font=font_ad)
    ad_width = ad_bbox[2] - ad_bbox[0]
    ad_x = center[0] - ad_width // 2
    ad_y = center[1] - radius * 0.45
    draw.text((ad_x, ad_y), ad_text, font=font_ad, fill=(0, 245, 255, 255))
    
    rig_text = "Rig"
    rig_bbox = draw.textbbox((0, 0), rig_text, font=font_rig)
    rig_width = rig_bbox[2] - rig_bbox[0]
    rig_x = center[0] - rig_width // 2
    rig_y = center[1] + radius * 0.05
    draw.text((rig_x, rig_y), rig_text, font=font_rig, fill=(0, 102, 255, 255))
    
    # Dividing line
    line_y = center[1]
    draw.line(
        [(center[0] - radius * 0.4, line_y), (center[0] + radius * 0.4, line_y)],
        fill=(0, 245, 255, 255),
        width=2
    )
    
    # Corner accents
    draw_corner_accents(draw, center, radius)
    
    # Border
    draw.polygon(shield_points, outline=(0, 245, 255, 255), width=4)
    
    return img

def main():
    print("🚀 Creating Unique AdRig Brand Logo...")
    
    print("  ⚡ Generating main launcher icon with 'AdRig' branding...")
    main_icon = create_adrig_icon(1024)
    main_icon.save('assets/icon/adrig_icon.png')
    print("  ✓ Saved: assets/icon/adrig_icon.png")
    
    print("  ⚡ Generating adaptive icon foreground...")
    foreground = create_foreground_icon(1024)
    foreground.save('assets/icon/adrig_icon_foreground.png')
    print("  ✓ Saved: assets/icon/adrig_icon_foreground.png")
    
    print("\n✨ Unique AdRig brand logo generated!")
    print("   Features:")
    print("   • Large 'AdRig' text in shield")
    print("   • 'Ad' (cyan) + 'Rig' (blue) split design")
    print("   • Circuit DNA double helix pattern")
    print("   • 4 corner targeting accents")
    print("   • Dividing line with circuit nodes")
    print("   • Unique brand identity - unmistakable")

if __name__ == '__main__':
    main()
