package com.oph.sentinel.ui

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Typography
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.Font
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.sp
import com.oph.sentinel.R

/** Colours copied from app/ui/css/tokens.css (the single source of truth for OPH Sentinel). */
object Oph {
    val appbar = Color(0xFF0D0F12)
    val page = Color(0xFF13161A)
    val panel = Color(0xFF1A1E23)
    val raised = Color(0xFF22272D)
    val border = Color(0xFF2C3239)
    val borderStrong = Color(0xFF3A414A)
    val text = Color(0xFFE6E9ED)
    val text2 = Color(0xFFA3ABB5)
    val muted = Color(0xFF6F7882)
    val inverse = Color(0xFF0D0F12)
    val accent = Color(0xFF65A637)
    val accentSoft = Color(0x2465A637)
    val link = Color(0xFF4FA8E8)
    val critical = Color(0xFFE5484D)
    val high = Color(0xFFF76808)
    val medium = Color(0xFFF5C518)
    val low = Color(0xFF3E9BFF)
    val info = Color(0xFF6F7882)
    val ok = accent
    val warn = medium
    val danger = critical

    fun severity(s: String) = when (s) {
        "critical" -> critical; "high" -> high; "medium" -> medium; "low" -> low; else -> info
    }
}

val PlexSans = FontFamily(
    Font(R.font.ibm_plex_sans_regular, FontWeight.Normal),
    Font(R.font.ibm_plex_sans_medium, FontWeight.Medium),
    Font(R.font.ibm_plex_sans_semibold, FontWeight.SemiBold),
)

private fun t(size: Int, w: FontWeight = FontWeight.Normal, lh: Double = 1.45) =
    TextStyle(fontFamily = PlexSans, fontSize = size.sp, fontWeight = w, lineHeight = (size * lh).sp)

private val typography = Typography(
    headlineSmall = t(20, FontWeight.SemiBold, 1.25),
    titleLarge = t(20, FontWeight.SemiBold, 1.25),
    titleMedium = t(16, FontWeight.SemiBold, 1.25),
    titleSmall = t(14, FontWeight.Medium),
    bodyLarge = t(16),
    bodyMedium = t(14),
    bodySmall = t(13),
    labelLarge = t(14, FontWeight.Medium),
    labelMedium = t(12, FontWeight.Medium),
    labelSmall = t(11, FontWeight.Medium),
)

private val colors = darkColorScheme(
    primary = Oph.accent,
    onPrimary = Oph.inverse,
    primaryContainer = Oph.accentSoft,
    onPrimaryContainer = Oph.text,
    secondary = Oph.link,
    background = Oph.page,
    onBackground = Oph.text,
    surface = Oph.panel,
    onSurface = Oph.text,
    surfaceVariant = Oph.raised,
    onSurfaceVariant = Oph.text2,
    surfaceContainer = Oph.panel,
    surfaceContainerHigh = Oph.raised,
    surfaceContainerHighest = Oph.raised,
    surfaceContainerLow = Oph.panel,
    outline = Oph.border,
    outlineVariant = Oph.border,
    error = Oph.danger,
    onError = Oph.text,
)

@Composable
fun OphTheme(content: @Composable () -> Unit) =
    MaterialTheme(colorScheme = colors, typography = typography, content = content)
