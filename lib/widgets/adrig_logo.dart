import 'package:flutter/material.dart';
import 'package:flutter_svg/flutter_svg.dart';

/// AdRig Logo - Simple, Clean, Professional
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
        // Professional AR logo SVG
        SvgPicture.asset(
          'assets/logo/adrig_ar_logo.svg',
          width: size,
          height: size,
          fit: BoxFit.contain,
        ),
        
        if (showText) ...[
          SizedBox(height: 16),
          Text(
            'AI THREAT INTELLIGENCE',
            style: TextStyle(
              fontSize: size * 0.15,
              color: Color(0xFF00D9FF),
              letterSpacing: 4,
              fontWeight: FontWeight.w600,
            ),
          ),
        ],
      ],
    );
  }
}
