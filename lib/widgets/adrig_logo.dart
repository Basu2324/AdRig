import 'package:flutter/material.dart';
import 'dart:math' as math;
import 'dart:ui' as ui;

/// AdRig Logo - Unique Brand Identity
/// Design: "AdRig" text integrated into shield with circuit DNA helix
class AdRigLogo extends StatelessWidget {
  final double size;
  final bool showText;
  
  const AdRigLogo({
    super.key,
    this.size = 120,
    this.showText = true,
  });

  @override
  Widget build(BuildContext context) {
    return Column(
      mainAxisSize: MainAxisSize.min,
      children: [
        // Unique AdRig shield with integrated branding
        SizedBox(
          width: size,
          height: size,
          child: CustomPaint(
            painter: _AdRigBrandPainter(size),
          ),
        ),
        
        if (showText) ...[
          const SizedBox(height: 20),
          // Holographic AdRig brand name
          ShaderMask(
            shaderCallback: (bounds) => ui.Gradient.linear(
              const Offset(0, 0),
              Offset(bounds.width, 0),
              [
                const Color(0xFF00F5FF), // Cyan
                const Color(0xFF0066FF), // Blue
                const Color(0xFF00F5FF), // Cyan
              ],
              [0.0, 0.5, 1.0],
            ),
            child: Text(
              'AdRig',
              style: TextStyle(
                fontSize: size * 0.4,
                fontWeight: FontWeight.w900,
                color: Colors.white,
                letterSpacing: 2,
                shadows: [
                  Shadow(
                    color: Color(0xFF00F5FF).withOpacity(0.5),
                    blurRadius: 20,
                  ),
                ],
              ),
            ),
          ),
          const SizedBox(height: 8),
          
          // Premium tagline
          Container(
            padding: EdgeInsets.symmetric(horizontal: 16, vertical: 6),
            decoration: BoxDecoration(
              gradient: LinearGradient(
                colors: [
                  Color(0xFF00F5FF).withOpacity(0.3),
                  Color(0xFF0066FF).withOpacity(0.3),
                ],
              ),
              borderRadius: BorderRadius.circular(16),
              border: Border.all(
                color: Color(0xFF00F5FF),
                width: 1.5,
              ),
              boxShadow: [
                BoxShadow(
                  color: Color(0xFF00F5FF).withOpacity(0.3),
                  blurRadius: 15,
                  spreadRadius: 2,
                ),
              ],
            ),
            child: Text(
              'AI THREAT INTELLIGENCE',
              style: TextStyle(
                fontSize: size * 0.11,
                color: Color(0xFF00F5FF),
                letterSpacing: 3,
                fontWeight: FontWeight.w800,
              ),
            ),
          ),
        ],
      ],
    );
  }
}

/// Custom painter with "AdRig" integrated into shield design
class _AdRigBrandPainter extends CustomPainter {
  final double size;
  
  _AdRigBrandPainter(this.size);
  
  @override
  void paint(Canvas canvas, Size canvasSize) {
    final center = Offset(canvasSize.width / 2, canvasSize.height / 2);
    final radius = size * 0.42;
    
    // Create shield path
    final shieldPath = _createShieldPath(center, radius);
    
    // Layer 1: Deep shadow
    canvas.drawPath(
      shieldPath.shift(Offset(3, 5)),
      Paint()
        ..color = Colors.black.withOpacity(0.5)
        ..maskFilter = MaskFilter.blur(BlurStyle.normal, 12),
    );
    
    // Layer 2: Dark metallic base
    final basePaint = Paint()
      ..shader = ui.Gradient.radial(
        center,
        radius,
        [
          Color(0xFF000820),
          Color(0xFF001840),
          Color(0xFF000a20),
        ],
        [0.0, 0.6, 1.0],
      );
    canvas.drawPath(shieldPath, basePaint);
    
    // Layer 3: Circuit DNA helix pattern (representing continuous protection)
    _drawCircuitDNA(canvas, center, radius, shieldPath);
    
    // Layer 4: "AdRig" text integrated into shield
    _drawAdRigBrand(canvas, center, radius);
    
    // Layer 5: Glowing borders
    _drawGlowingBorders(canvas, shieldPath, center, radius);
    
    // Layer 6: Corner accents (4 corners representing security coverage)
    _drawCornerAccents(canvas, center, radius);
  }
  
  Path _createShieldPath(Offset center, double radius) {
    final path = Path();
    final cx = center.dx;
    final cy = center.dy;
    
    // Modern shield
    path.moveTo(cx, cy - radius * 1.05);
    path.cubicTo(
      cx - radius * 0.3, cy - radius * 1.0,
      cx - radius * 0.7, cy - radius * 0.95,
      cx - radius * 0.85, cy - radius * 0.6,
    );
    path.cubicTo(
      cx - radius * 0.95, cy - radius * 0.2,
      cx - radius * 0.95, cy + radius * 0.2,
      cx - radius * 0.75, cy + radius * 0.55,
    );
    path.cubicTo(
      cx - radius * 0.5, cy + radius * 0.85,
      cx - radius * 0.2, cy + radius * 1.0,
      cx, cy + radius * 1.12,
    );
    path.cubicTo(
      cx + radius * 0.2, cy + radius * 1.0,
      cx + radius * 0.5, cy + radius * 0.85,
      cx + radius * 0.75, cy + radius * 0.55,
    );
    path.cubicTo(
      cx + radius * 0.95, cy + radius * 0.2,
      cx + radius * 0.95, cy - radius * 0.2,
      cx + radius * 0.85, cy - radius * 0.6,
    );
    path.cubicTo(
      cx + radius * 0.7, cy - radius * 0.95,
      cx + radius * 0.3, cy - radius * 1.0,
      cx, cy - radius * 1.05,
    );
    path.close();
    return path;
  }
  
  void _drawCircuitDNA(Canvas canvas, Offset center, double radius, Path clipPath) {
    canvas.save();
    canvas.clipPath(clipPath);
    
    // DNA double helix circuit pattern
    final helixPaint = Paint()
      ..strokeWidth = 2.0
      ..style = PaintingStyle.stroke;
    
    // Left helix strand
    final leftPath = Path();
    final rightPath = Path();
    
    for (double t = 0; t <= 1.0; t += 0.05) {
      final y = center.dy - radius * 0.8 + (t * radius * 1.6);
      final leftX = center.dx - radius * 0.3 * math.sin(t * math.pi * 4);
      final rightX = center.dx + radius * 0.3 * math.sin(t * math.pi * 4);
      
      if (t == 0) {
        leftPath.moveTo(leftX, y);
        rightPath.moveTo(rightX, y);
      } else {
        leftPath.lineTo(leftX, y);
        rightPath.lineTo(rightX, y);
      }
    }
    
    // Draw helix strands with gradient
    helixPaint.shader = ui.Gradient.linear(
      Offset(center.dx, center.dy - radius),
      Offset(center.dx, center.dy + radius),
      [
        Color(0xFF00F5FF).withOpacity(0.6),
        Color(0xFF0066FF).withOpacity(0.4),
      ],
    );
    
    canvas.drawPath(leftPath, helixPaint);
    canvas.drawPath(rightPath, helixPaint);
    
    // Connection bars between helixes (circuit connections)
    for (double t = 0; t <= 1.0; t += 0.15) {
      final y = center.dy - radius * 0.8 + (t * radius * 1.6);
      final leftX = center.dx - radius * 0.3 * math.sin(t * math.pi * 4);
      final rightX = center.dx + radius * 0.3 * math.sin(t * math.pi * 4);
      
      canvas.drawLine(
        Offset(leftX, y),
        Offset(rightX, y),
        Paint()
          ..color = Color(0xFF00F5FF).withOpacity(0.3)
          ..strokeWidth = 1.5,
      );
      
      // Connection nodes
      canvas.drawCircle(
        Offset(leftX, y),
        2,
        Paint()..color = Color(0xFF00F5FF),
      );
      canvas.drawCircle(
        Offset(rightX, y),
        2,
        Paint()..color = Color(0xFF00F5FF),
      );
    }
    
    canvas.restore();
  }
  
  void _drawAdRigBrand(Canvas canvas, Offset center, double radius) {
    // Draw "AdRig" text prominently in the shield
    
    // "Ad" in top half
    final adTextPainter = TextPainter(
      text: TextSpan(
        text: 'Ad',
        style: TextStyle(
          fontSize: radius * 0.5,
          fontWeight: FontWeight.w900,
          foreground: Paint()
            ..shader = ui.Gradient.linear(
              Offset(center.dx - radius * 0.3, center.dy - radius * 0.3),
              Offset(center.dx + radius * 0.3, center.dy - radius * 0.3),
              [
                Color(0xFF00F5FF),
                Color(0xFF00D4FF),
              ],
            ),
          shadows: [
            Shadow(
              color: Color(0xFF00F5FF),
              blurRadius: 15,
            ),
          ],
        ),
      ),
      textDirection: TextDirection.ltr,
    );
    
    adTextPainter.layout();
    adTextPainter.paint(
      canvas,
      Offset(
        center.dx - adTextPainter.width / 2,
        center.dy - radius * 0.45,
      ),
    );
    
    // "Rig" in bottom half
    final rigTextPainter = TextPainter(
      text: TextSpan(
        text: 'Rig',
        style: TextStyle(
          fontSize: radius * 0.48,
          fontWeight: FontWeight.w900,
          foreground: Paint()
            ..shader = ui.Gradient.linear(
              Offset(center.dx - radius * 0.3, center.dy + radius * 0.3),
              Offset(center.dx + radius * 0.3, center.dy + radius * 0.3),
              [
                Color(0xFF0066FF),
                Color(0xFF6B00FF),
              ],
            ),
          shadows: [
            Shadow(
              color: Color(0xFF0066FF),
              blurRadius: 15,
            ),
          ],
        ),
      ),
      textDirection: TextDirection.ltr,
    );
    
    rigTextPainter.layout();
    rigTextPainter.paint(
      canvas,
      Offset(
        center.dx - rigTextPainter.width / 2,
        center.dy + radius * 0.05,
      ),
    );
    
    // Dividing line between Ad and Rig (like circuit board trace)
    final dividerPaint = Paint()
      ..shader = ui.Gradient.linear(
        Offset(center.dx - radius * 0.4, center.dy),
        Offset(center.dx + radius * 0.4, center.dy),
        [
          Colors.transparent,
          Color(0xFF00F5FF),
          Colors.transparent,
        ],
      )
      ..strokeWidth = 2.0;
    
    canvas.drawLine(
      Offset(center.dx - radius * 0.4, center.dy),
      Offset(center.dx + radius * 0.4, center.dy),
      dividerPaint,
    );
    
    // Small circuit nodes on divider
    for (int i = -2; i <= 2; i++) {
      final x = center.dx + (i * radius * 0.2);
      canvas.drawCircle(
        Offset(x, center.dy),
        2.5,
        Paint()..color = Color(0xFF00F5FF),
      );
      
      // Glow around nodes
      canvas.drawCircle(
        Offset(x, center.dy),
        5,
        Paint()
          ..color = Color(0xFF00F5FF).withOpacity(0.3)
          ..maskFilter = MaskFilter.blur(BlurStyle.normal, 4),
      );
    }
  }
  
  void _drawGlowingBorders(Canvas canvas, Path shieldPath, Offset center, double radius) {
    // Outer glow
    canvas.drawPath(
      shieldPath,
      Paint()
        ..color = Color(0xFF00F5FF).withOpacity(0.3)
        ..style = PaintingStyle.stroke
        ..strokeWidth = 6
        ..maskFilter = MaskFilter.blur(BlurStyle.outer, 15),
    );
    
    // Main gradient border
    canvas.drawPath(
      shieldPath,
      Paint()
        ..shader = ui.Gradient.linear(
          Offset(center.dx, center.dy - radius),
          Offset(center.dx, center.dy + radius),
          [
            Color(0xFF00F5FF),
            Color(0xFF0066FF),
            Color(0xFF6B00FF),
          ],
        )
        ..style = PaintingStyle.stroke
        ..strokeWidth = 3,
    );
  }
  
  void _drawCornerAccents(Canvas canvas, Offset center, double radius) {
    // 4 corner glowing accents (representing 360° protection)
    final corners = [
      Offset(center.dx - radius * 0.6, center.dy - radius * 0.5), // Top-left
      Offset(center.dx + radius * 0.6, center.dy - radius * 0.5), // Top-right
      Offset(center.dx - radius * 0.5, center.dy + radius * 0.6), // Bottom-left
      Offset(center.dx + radius * 0.5, center.dy + radius * 0.6), // Bottom-right
    ];
    
    for (final corner in corners) {
      // Glowing dot
      canvas.drawCircle(
        corner,
        4,
        Paint()
          ..color = Color(0xFF00F5FF)
          ..maskFilter = MaskFilter.blur(BlurStyle.normal, 8),
      );
      
      // Core dot
      canvas.drawCircle(
        corner,
        2,
        Paint()..color = Colors.white,
      );
      
      // Small cross lines (targeting reticle style)
      final crossSize = 8.0;
      canvas.drawLine(
        Offset(corner.dx - crossSize, corner.dy),
        Offset(corner.dx + crossSize, corner.dy),
        Paint()
          ..color = Color(0xFF00F5FF).withOpacity(0.6)
          ..strokeWidth = 1.5,
      );
      canvas.drawLine(
        Offset(corner.dx, corner.dy - crossSize),
        Offset(corner.dx, corner.dy + crossSize),
        Paint()
          ..color = Color(0xFF00F5FF).withOpacity(0.6)
          ..strokeWidth = 1.5,
      );
    }
  }
  
  @override
  bool shouldRepaint(covariant CustomPainter oldDelegate) => false;
}

/// Animated version with breathing glow
class AnimatedAdRigLogo extends StatefulWidget {
  final double size;
  
  const AnimatedAdRigLogo({
    super.key,
    this.size = 120,
  });

  @override
  State<AnimatedAdRigLogo> createState() => _AnimatedAdRigLogoState();
}

class _AnimatedAdRigLogoState extends State<AnimatedAdRigLogo>
    with TickerProviderStateMixin {
  late AnimationController _pulseController;
  late AnimationController _glowController;
  late Animation<double> _pulseAnimation;
  late Animation<double> _glowAnimation;

  @override
  void initState() {
    super.initState();
    
    _pulseController = AnimationController(
      duration: const Duration(milliseconds: 2500),
      vsync: this,
    )..repeat(reverse: true);

    _glowController = AnimationController(
      duration: const Duration(milliseconds: 3000),
      vsync: this,
    )..repeat(reverse: true);

    _pulseAnimation = Tween<double>(
      begin: 0.97,
      end: 1.03,
    ).animate(CurvedAnimation(
      parent: _pulseController,
      curve: Curves.easeInOut,
    ));

    _glowAnimation = Tween<double>(
      begin: 15,
      end: 35,
    ).animate(CurvedAnimation(
      parent: _glowController,
      curve: Curves.easeInOut,
    ));
  }

  @override
  void dispose() {
    _pulseController.dispose();
    _glowController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return AnimatedBuilder(
      animation: Listenable.merge([_pulseAnimation, _glowAnimation]),
      builder: (context, child) {
        return Transform.scale(
          scale: _pulseAnimation.value,
          child: Container(
            decoration: BoxDecoration(
              shape: BoxShape.circle,
              boxShadow: [
                BoxShadow(
                  color: Color(0xFF00F5FF).withOpacity(0.4),
                  blurRadius: _glowAnimation.value,
                  spreadRadius: _glowAnimation.value * 0.3,
                ),
              ],
            ),
            child: AdRigLogo(
              size: widget.size,
              showText: true,
            ),
          ),
        );
      },
    );
  }
}
