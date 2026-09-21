# Draws Mole's icon: a mole with a pink nose and cream digging claws, rising from
# an earth mound on a warm dark rounded square, at every size Windows asks for,
# plus a multi-size .ico. Köstebek — duvarı yıkmaz, altından geçer.
#
#   powershell -ExecutionPolicy Bypass -File scripts\make-icons.ps1

Add-Type -AssemblyName System.Drawing
$ErrorActionPreference = 'Stop'
$out = Join-Path $PSScriptRoot '..\icons'
New-Item -ItemType Directory -Force $out | Out-Null

function Colour($hex) { [System.Drawing.ColorTranslator]::FromHtml($hex) }
function Lift($c, $d) {
    [System.Drawing.Color]::FromArgb($c.A,
        [Math]::Min(255, $c.R + $d), [Math]::Min(255, $c.G + $d), [Math]::Min(255, $c.B + $d))
}

# Fill an ellipse (in fractional 0..1 coordinates) with a top-left-lit gradient.
function Blob($g, [single]$S, [single]$cx, [single]$cy, [single]$w, [single]$h, $hex, [int]$lift) {
    $x = ($cx - $w / 2) * $S; $y = ($cy - $h / 2) * $S
    $rw = $w * $S; $rh = $h * $S
    $rect = New-Object System.Drawing.RectangleF $x, $y, $rw, $rh
    $base = Colour $hex
    $brush = New-Object System.Drawing.Drawing2D.LinearGradientBrush `
        $rect, (Lift $base $lift), (Lift $base (-[int]($lift * 0.7))), 55.0
    $g.FillEllipse($brush, $rect)
    $brush.Dispose()
}

function Draw([int]$size) {
    $S = [single]$size
    $bmp = New-Object System.Drawing.Bitmap $size, $size
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = 'AntiAlias'
    $g.Clear([System.Drawing.Color]::Transparent)

    # Rounded background with a warm, earthy vertical gradient.
    $r = [Math]::Max(2, [int]($size * 0.18))
    $path = New-Object System.Drawing.Drawing2D.GraphicsPath
    $path.AddArc(0, 0, 2 * $r, 2 * $r, 180, 90)
    $path.AddArc($size - 2 * $r - 1, 0, 2 * $r, 2 * $r, 270, 90)
    $path.AddArc($size - 2 * $r - 1, $size - 2 * $r - 1, 2 * $r, 2 * $r, 0, 90)
    $path.AddArc(0, $size - 2 * $r - 1, 2 * $r, 2 * $r, 90, 90)
    $path.CloseFigure()
    $bgRect = New-Object System.Drawing.RectangleF 0, 0, $S, $S
    $bg = New-Object System.Drawing.Drawing2D.LinearGradientBrush `
        $bgRect, (Colour '#1c1712'), (Colour '#0c0a07'), 90.0
    $g.FillPath($bg, $path)

    # Clip to the rounded square so the mound can't spill past the corners.
    $g.SetClip($path)

    # Earth mound the mole rises from: a broad brown ellipse across the bottom.
    Blob $g $S 0.5 1.06 1.30 0.60 '#3a2a1c' 22

    # Two cream digging claws resting on the rim, drawn first so the body overlaps.
    foreach ($sx in -1, 1) {
        Blob $g $S (0.5 + $sx * 0.20) 0.74 0.20 0.16 '#e7dcc7' 24
    }
    # Claw nails: thin dark slivers (invisible at tiny sizes, that's fine).
    if ($size -ge 48) {
        $pen = New-Object System.Drawing.Pen (Colour '#8f7f66'), ([single]($size / 128.0))
        foreach ($sx in -1, 1) {
            $bx = (0.5 + $sx * 0.20) * $S
            foreach ($o in -0.05, 0, 0.05) {
                $g.DrawLine($pen, ($bx + $o * $S), (0.70 * $S), ($bx + $o * $S), (0.79 * $S))
            }
        }
        $pen.Dispose()
    }

    # Mole body and rounded head.
    Blob $g $S 0.5 0.52 0.62 0.66 '#6f6b76' 26
    Blob $g $S 0.5 0.60 0.40 0.34 '#807c88' 24   # lighter belly

    # Snout pointing down to the nose.
    Blob $g $S 0.5 0.66 0.26 0.26 '#5f5b67' 20
    # Pink nose.
    Blob $g $S 0.5 0.70 0.135 0.115 '#ef93aa' 30

    # Closed, content eyes (moles barely see): two short dark arcs.
    $eyePen = New-Object System.Drawing.Pen (Colour '#2b2833'), ([single][Math]::Max(1.0, $size / 42.0))
    $eyePen.StartCap = 'Round'; $eyePen.EndCap = 'Round'
    foreach ($sx in -1, 1) {
        $ex = (0.5 + $sx * 0.135) * $S
        $g.DrawArc($eyePen, ($ex - 0.055 * $S), (0.48 * $S), (0.11 * $S), (0.09 * $S), 20, 140)
    }
    $eyePen.Dispose()

    $g.Dispose()
    return $bmp
}

$pngs = @{}
foreach ($size in 16, 32, 48, 64, 128, 256) {
    $bmp = Draw $size
    $file = Join-Path $out "${size}x${size}.png"
    $bmp.Save($file, [System.Drawing.Imaging.ImageFormat]::Png)
    $pngs[$size] = [IO.File]::ReadAllBytes($file)
    $bmp.Dispose()
}
Copy-Item (Join-Path $out '256x256.png') (Join-Path $out 'icon.png') -Force

# A .ico is a directory of PNG images.
$sizes = 16, 32, 48, 64, 128, 256
$stream = New-Object IO.MemoryStream
$w = New-Object IO.BinaryWriter $stream
$w.Write([uint16]0); $w.Write([uint16]1); $w.Write([uint16]$sizes.Count)
$offset = 6 + 16 * $sizes.Count
foreach ($s in $sizes) {
    $b = if ($s -ge 256) { 0 } else { $s }
    $w.Write([byte]$b); $w.Write([byte]$b); $w.Write([byte]0); $w.Write([byte]0)
    $w.Write([uint16]1); $w.Write([uint16]32)
    $w.Write([uint32]$pngs[$s].Length); $w.Write([uint32]$offset)
    $offset += $pngs[$s].Length
}
foreach ($s in $sizes) { $w.Write($pngs[$s]) }
[IO.File]::WriteAllBytes((Join-Path $out 'icon.ico'), $stream.ToArray())
'icons written to ' + (Resolve-Path $out)
