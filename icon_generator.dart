import 'dart:io';
import 'dart:ui' as ui;
import 'package:flutter/material.dart';
import 'package:flutter/rendering.dart';

/// AdRig Icon Generator
/// Run this to generate app launcher icons
void main() async {
  WidgetsFlutterBinding.ensureInitialized();
  
  print('🎨 Generating AdRig App Icons...');
  
  // Create icon directory
  final iconDir = Directory('assets/icon');
  if (!await iconDir.exists()) {
    await iconDir.create(recursive: true);
  }
  
  // Generate main icon (1024x1024)
  await _generateIcon('assets/icon/adrig_icon.png', 1024);
  
  // Generate foreground for adaptive icon
  await _generateIcon('assets/icon/adrig_icon_foreground.png', 1024, transparent: true);
  
  print('✅ Icons generated successfully!');
  print('📝 Run: flutter pub run flutter_launcher_icons');
}

Future<void> _generateIcon(String path, int size, {bool transparent = false}) async {
  final recorder = ui.PictureRecorder();
  final canvas = Canvas(recorder);
  
  // Draw icon
  _drawAdRigIcon(canvas, Size(size.toDouble(), size.toDouble()), transparent);
  
  // Convert to image
  final picture = recorder.endRecording();
  final image = await picture.toImage(size, size);
  final byteData = await image.toByteData(format: ui.ImageByteFormat.png);
  
  // Save to file
  final file = File(path);
  await file.writeAsBytes(byteData!.buffer.asUint8List());
  
  print('✓ Generated: $path');
}

void _drawAdRigIcon(Canvas canvas, Size size, bool transparent) {
  final center = Offset(size.width / 2, size.height / 2);
  final radius = size.width * 0.4;
  
  // Background (if not transparent)
  if (!transparent) {
    final bgPaint = Paint()
      ..shader = ui.Gradient.linear(
        Offset(0, 0),
        Offset(size.width, size.height),
        [
          Color(0xFF667eea), // Purple-blue
          Color(0xFF764ba2), // Purple
        ],
      );
    canvas.drawRect(Offset.zero & size, bgPaint);
  }
  
  // Draw hexagonal shield
  final path = Path();
  for (int i = 0; i < 6; i++) {
    final angle = (i * 60 - 90) * 3.14159 / 180;
    final x = center.dx + radius * _cos(angle);
    final y = center.dy + radius * _sin(angle);
    
    if (i == 0) {
      path.moveTo(x, y);
    } else {
      path.lineTo(x, y);
    }
  }
  path.close();
  
  // Fill hexagon
  final hexPaint = Paint()
    ..shader = ui.Gradient.linear(
      Offset(center.dx - radius, center.dy - radius),
      Offset(center.dx + radius, center.dy + radius),
      [
        Color(0xFF667eea),
        Color(0xFF764ba2),
        Color(0xFFf093fb),
      ],
    );
  canvas.drawPath(path, hexPaint);
  
  // Border
  final borderPaint = Paint()
    ..color = Colors.white.withOpacity(0.5)
    ..style = PaintingStyle.stroke
    ..strokeWidth = size.width * 0.015;
  canvas.drawPath(path, borderPaint);
  
  // Draw "AR" text
  final textSpan = TextSpan(
    text: 'AR',
    style: TextStyle(
      fontSize: radius * 1.2,
      fontWeight: FontWeight.w900,
      color: Colors.white,
      shadows: [
        Shadow(
          blurRadius: 10,
          color: Colors.black.withOpacity(0.3),
          offset: Offset(0, 5),
        ),
      ],
    ),
  );
  
  final textPainter = TextPainter(
    text: textSpan,
    textDirection: TextDirection.ltr,
  );
  
  textPainter.layout();
  textPainter.paint(
    canvas,
    Offset(
      center.dx - textPainter.width / 2,
      center.dy - textPainter.height / 2,
    ),
  );
}

double _cos(double angle) {
  // Simple approximation
  return angle.cos();
}

double _sin(double angle) {
  return angle.sin();
}

extension on double {
  double cos() {
    double x = this;
    while (x > 6.28318530718) x -= 6.28318530718;
    while (x < 0) x += 6.28318530718;
    
    double result = 1.0;
    double term = 1.0;
    for (int i = 1; i < 10; i++) {
      term *= -x * x / ((2 * i - 1) * (2 * i));
      result += term;
    }
    return result;
  }
  
  double sin() {
    double x = this;
    while (x > 6.28318530718) x -= 6.28318530718;
    while (x < 0) x += 6.28318530718;
    
    double result = x;
    double term = x;
    for (int i = 1; i < 10; i++) {
      term *= -x * x / ((2 * i) * (2 * i + 1));
      result += term;
    }
    return result;
  }
}
