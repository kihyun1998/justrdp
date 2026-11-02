# #556 end-to-end workload: runs at every rdpbench logon, then signs the session out.
$dir = "$env:USERPROFILE\bench"
$log = "$dir\log.txt"
function Mark($what) { "$((Get-Date).ToString('o')) $what" | Add-Content $log }
Mark 'start'
Start-Sleep -Seconds 5

# Office: type into Notepad, then scroll a long text.
$text = "$dir\long.txt"
if (!(Test-Path $text)) {
    1..2000 | ForEach-Object { "Line $_ : The quick brown fox jumps over the lazy dog. 0123456789" } |
        Set-Content $text
}
Mark 'office'
$notepad = Start-Process notepad $text -PassThru
Start-Sleep -Seconds 3
$shell = New-Object -ComObject WScript.Shell
$null = $shell.AppActivate($notepad.Id)
foreach ($c in ('Measuring justrdp against FreeRDP. ' * 3).ToCharArray()) {
    $shell.SendKeys([string]$c)
    Start-Sleep -Milliseconds 80
}
1..50 | ForEach-Object { $shell.SendKeys('{PGDN}'); Start-Sleep -Milliseconds 300 }
Stop-Process -Id $notepad.Id -Force

# Heavy: a full-screen animation for 30 s.
Mark 'heavy'
Add-Type -AssemblyName System.Windows.Forms, System.Drawing
$form = New-Object Windows.Forms.Form
$form.FormBorderStyle = 'None'
$form.WindowState = 'Maximized'
$form.BackColor = [Drawing.Color]::Black
$script:tick = 0
$form.Add_Paint({
    $g = $_.Graphics
    $w = [Math]::Max(1, $form.ClientSize.Width - 160)
    $h = [Math]::Max(1, $form.ClientSize.Height - 160)
    for ($k = 0; $k -lt 12; $k++) {
        $x = ($script:tick * 7 + $k * 97) % $w
        $y = ($script:tick * 5 + $k * 61) % $h
        $color = [Drawing.Color]::FromArgb(255, ($k * 20) % 256, ($script:tick * 3) % 256, (255 - $k * 20) % 256)
        $brush = New-Object Drawing.SolidBrush $color
        $g.FillEllipse($brush, $x, $y, 160, 160)
        $brush.Dispose()
    }
})
$frame = New-Object Windows.Forms.Timer
$frame.Interval = 16
$frame.Add_Tick({ $script:tick++; $form.Invalidate() })
$stop = New-Object Windows.Forms.Timer
$stop.Interval = 30000
$stop.Add_Tick({ $form.Close() })
$frame.Start()
$stop.Start()
[Windows.Forms.Application]::Run($form)

Mark 'logoff'
Start-Sleep -Seconds 2
shutdown.exe /l /f
