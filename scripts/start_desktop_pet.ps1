param([switch]$ValidateOnly)

$ErrorActionPreference = "Stop"
Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase, System.Xaml

$xaml = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="审计小狐 · AgentMeter-Gov 桌面巡检助手"
        Width="172" Height="198" WindowStyle="None" ResizeMode="NoResize"
        AllowsTransparency="True" Background="Transparent" Topmost="True"
        ShowInTaskbar="False" Focusable="True"
        ToolTip="中国计量大学学生作品 · 双击小狐打开安全审计平台">
  <Grid Background="Transparent">
    <Border x:Name="SpeechBubble" HorizontalAlignment="Center" VerticalAlignment="Top"
            Margin="0,1,0,0" Padding="9,5" MinWidth="62" MaxWidth="166"
            Background="#F7FFFFFF" BorderBrush="#B9CDDF" BorderThickness="1"
            CornerRadius="11" Opacity="0" Panel.ZIndex="2">
      <Border.Effect><DropShadowEffect BlurRadius="9" ShadowDepth="2" Opacity="0.16"/></Border.Effect>
      <TextBlock x:Name="SpeechText" Text="安全巡检中" Foreground="#36536D"
                 FontFamily="Microsoft YaHei" FontSize="10" TextAlignment="Center" TextWrapping="Wrap"/>
    </Border>

    <Canvas x:Name="PetRoot" Width="92" Height="103" Margin="0,38,0,0" Visibility="Collapsed"
            HorizontalAlignment="Center" VerticalAlignment="Top" RenderTransformOrigin="0.5,0.5">
      <Ellipse Canvas.Left="15" Canvas.Top="91" Width="62" Height="10" Fill="#293F5A" Opacity="0.16"/>

      <!-- “量量”的双耳取意于新莽嘉量，造型采用现代机器人语言 -->
      <Path Canvas.Left="0" Canvas.Top="24" Fill="#E7F2FB" Stroke="#225D95" StrokeThickness="4"
            StrokeStartLineCap="Round" StrokeEndLineCap="Round" Data="M 22,2 C 3,-2 3,29 22,27"/>
      <Path Canvas.Left="70" Canvas.Top="24" Fill="#E7F2FB" Stroke="#225D95" StrokeThickness="4"
            StrokeStartLineCap="Round" StrokeEndLineCap="Round" Data="M 0,2 C 19,-2 19,29 0,27"/>
      <Rectangle x:Name="LeftArm" Canvas.Left="7" Canvas.Top="52" Width="14" Height="31"
                 RadiusX="7" RadiusY="7" Fill="#D9ECFB" Stroke="#225D95" StrokeThickness="2.5"
                 RenderTransformOrigin="0.5,0.1">
        <Rectangle.RenderTransform><RotateTransform Angle="16"/></Rectangle.RenderTransform>
      </Rectangle>
      <Rectangle x:Name="RightArm" Canvas.Left="71" Canvas.Top="52" Width="14" Height="31"
                 RadiusX="7" RadiusY="7" Fill="#D9ECFB" Stroke="#225D95" StrokeThickness="2.5"
                 RenderTransformOrigin="0.5,0.1">
        <Rectangle.RenderTransform><RotateTransform Angle="-16"/></Rectangle.RenderTransform>
      </Rectangle>

      <Border Canvas.Left="17" Canvas.Top="13" Width="58" Height="72"
              CornerRadius="24" BorderBrush="#225D95" BorderThickness="2.5">
        <Border.Background>
          <LinearGradientBrush StartPoint="0,0" EndPoint="1,1">
            <GradientStop Color="#FAFDFF" Offset="0"/><GradientStop Color="#D6EAFB" Offset="1"/>
          </LinearGradientBrush>
        </Border.Background>
      </Border>
      <Border Canvas.Left="24" Canvas.Top="25" Width="44" Height="29" CornerRadius="15" Background="#E8F4FD"/>
      <Ellipse x:Name="LeftEye" Canvas.Left="31" Canvas.Top="35" Width="6" Height="9" Fill="#284D70"/>
      <Ellipse x:Name="RightEye" Canvas.Left="55" Canvas.Top="35" Width="6" Height="9" Fill="#284D70"/>
      <Path Canvas.Left="42" Canvas.Top="48" Stroke="#5C7891" StrokeThickness="2"
            Data="M 0,0 Q 4,5 8,0"/>

      <Path Canvas.Left="35" Canvas.Top="59" Fill="#225D95" Data="M 0,0 L 22,0 L 20,17 Q 11,24 2,17 Z"/>
      <TextBlock Canvas.Left="39" Canvas.Top="59" Text="量" Foreground="White"
                 FontFamily="Microsoft YaHei" FontWeight="Bold" FontSize="13"/>

      <Rectangle x:Name="LeftFoot" Canvas.Left="17" Canvas.Top="79" Width="28" Height="17"
                 RadiusX="9" RadiusY="9" Fill="#B7D8F3" Stroke="#225D95" StrokeThickness="2.5"/>
      <Rectangle x:Name="RightFoot" Canvas.Left="48" Canvas.Top="79" Width="28" Height="17"
                 RadiusX="9" RadiusY="9" Fill="#B7D8F3" Stroke="#225D95" StrokeThickness="2.5"/>
    </Canvas>
    <Image x:Name="PetImage" Width="166" Height="166" Margin="3,30,3,2"
           HorizontalAlignment="Center" VerticalAlignment="Top" Stretch="Uniform" Panel.ZIndex="1">
      <Image.Effect><DropShadowEffect BlurRadius="8" ShadowDepth="3" Opacity="0.22"/></Image.Effect>
    </Image>
    <Border x:Name="DockPeek" Width="64" Height="68" CornerRadius="30" Cursor="Hand"
            HorizontalAlignment="Center" VerticalAlignment="Center" Visibility="Collapsed"
            Background="#F5FFFFFF" BorderBrush="#7FAED3" BorderThickness="1.5" Panel.ZIndex="4"
            ToolTip="单击恢复桌面宠物">
      <Border.Effect><DropShadowEffect BlurRadius="8" ShadowDepth="2" Opacity="0.22"/></Border.Effect>
    </Border>
    <Ellipse x:Name="SchoolBadge" Width="22" Height="22" Margin="78,129,0,0"
             HorizontalAlignment="Left" VerticalAlignment="Top" Stroke="White"
             StrokeThickness="1.4" Panel.ZIndex="3"/>
  </Grid>
</Window>
'@

$reader = [System.Xml.XmlReader]::Create([System.IO.StringReader]::new($xaml))
$window = [System.Windows.Markup.XamlReader]::Load($reader)
if ($ValidateOnly) {
  "Desktop pet XAML is valid."
  return
}

$petLogPath = Join-Path $env:LOCALAPPDATA "AgentMeter-Gov\desktop-pet-startup.log"
function Write-PetLog([string]$message) {
  try {
    New-Item -ItemType Directory -Path (Split-Path -Parent $petLogPath) -Force | Out-Null
    Add-Content -LiteralPath $petLogPath -Value ("{0:o} {1}" -f (Get-Date), $message) -Encoding UTF8
  } catch { }
}

# Closing the pet only docks it to the screen edge, so the process keeps running
# and keeps holding this mutex. A second launch used to `return` silently, which
# meant clicking the Start menu entry to bring a docked pet back did nothing at
# all: no window, no message, no log. Signal the running instance to un-dock
# instead of exiting without a trace.
$showEventName = "Local\AgentMeterGovDesktopPetShow"
$hideEventName = "Local\AgentMeterGovDesktopPetHide"
$createdNew = $false
$mutex = [System.Threading.Mutex]::new($true, "Local\AgentMeterGovDesktopPet", [ref]$createdNew)
if (-not $createdNew) {
  try {
    $existing = [System.Threading.EventWaitHandle]::OpenExisting($showEventName)
    [void]$existing.Set()
    $existing.Dispose()
    Write-PetLog "desktop pet already running; signaled the existing instance to show"
  } catch {
    Write-PetLog "desktop pet already running but could not be signaled: $($_.Exception.Message)"
  }
  return
}

$createdShowEvent = $false
$script:showRequest = [System.Threading.EventWaitHandle]::new(
  $false,
  [System.Threading.EventResetMode]::AutoReset,
  $showEventName,
  [ref]$createdShowEvent)
$createdHideEvent = $false
$script:hideRequest = [System.Threading.EventWaitHandle]::new(
  $false,
  [System.Threading.EventResetMode]::AutoReset,
  $hideEventName,
  [ref]$createdHideEvent)

$petRoot = $window.FindName("PetRoot")
$speechBubble = $window.FindName("SpeechBubble")
$speechText = $window.FindName("SpeechText")
$leftEye = $window.FindName("LeftEye")
$rightEye = $window.FindName("RightEye")
$leftArm = $window.FindName("LeftArm")
$rightArm = $window.FindName("RightArm")
$leftFoot = $window.FindName("LeftFoot")
$rightFoot = $window.FindName("RightFoot")
$petImage = $window.FindName("PetImage")
$dockPeek = $window.FindName("DockPeek")
$schoolBadge = $window.FindName("SchoolBadge")

$baseRoot = Split-Path -Parent $PSScriptRoot
$serviceBaseUrl = "http://127.0.0.1:8765"
$serviceUrlFile = Join-Path $PSScriptRoot "service-base-url.txt"
if (Test-Path -LiteralPath $serviceUrlFile -PathType Leaf) {
  $configuredServiceUrl = (Get-Content -LiteralPath $serviceUrlFile -Raw).Trim().TrimEnd("/")
  if ($configuredServiceUrl -match '^http://(127\.0\.0\.1|localhost|\[::1\]):\d+$') {
    $serviceBaseUrl = $configuredServiceUrl
  }
}
$frontendCandidates = @(
  (Join-Path $baseRoot "AgentMeter-Gov\frontend"),
  (Join-Path $baseRoot "backend\_internal\frontend")
)
$frontendRoot = $frontendCandidates |
  Where-Object { Test-Path -LiteralPath $_ -PathType Container } |
  Select-Object -First 1
if (-not $frontendRoot) { throw "找不到 AgentMeter-Gov 前端素材目录。" }
$assetPath = Join-Path $frontendRoot "assets\desktop-pet-audit-fox.png"
$logoPath = Join-Path $frontendRoot "assets\cjlu-logo.jpg"
if (-not (Test-Path -LiteralPath $assetPath)) { throw "桌面宠物素材不存在：$assetPath" }
if (-not (Test-Path -LiteralPath $logoPath)) { throw "中国计量大学校徽不存在：$logoPath" }
$petBitmap = [System.Windows.Media.Imaging.BitmapImage]::new()
$petBitmap.BeginInit()
$petBitmap.CacheOption = [System.Windows.Media.Imaging.BitmapCacheOption]::OnLoad
  $petBitmap.DecodePixelWidth = 420
$petBitmap.UriSource = [Uri]::new($assetPath)
$petBitmap.EndInit()
$petBitmap.Freeze()
$petImage.Source = $petBitmap
$dockPeekBrush = [System.Windows.Media.ImageBrush]::new($petBitmap)
$dockPeekBrush.Stretch = [System.Windows.Media.Stretch]::UniformToFill
$dockPeekBrush.ViewboxUnits = [System.Windows.Media.BrushMappingMode]::RelativeToBoundingBox
$dockPeekBrush.Viewbox = [System.Windows.Rect]::new(0.14, 0.0, 0.72, 0.58)
$dockPeek.Background = $dockPeekBrush

$logoBitmap = [System.Windows.Media.Imaging.BitmapImage]::new()
$logoBitmap.BeginInit()
$logoBitmap.CacheOption = [System.Windows.Media.Imaging.BitmapCacheOption]::OnLoad
$logoBitmap.DecodePixelWidth = 280
$logoBitmap.UriSource = [Uri]::new($logoPath)
$logoBitmap.EndInit()
$logoBitmap.Freeze()
$badgeBrush = [System.Windows.Media.ImageBrush]::new($logoBitmap)
$badgeBrush.Stretch = [System.Windows.Media.Stretch]::Fill
$badgeBrush.ViewboxUnits = [System.Windows.Media.BrushMappingMode]::RelativeToBoundingBox
$badgeBrush.Viewbox = [System.Windows.Rect]::new(0.205, 0.065, 0.59, 0.58)
$schoolBadge.Fill = $badgeBrush

$workArea = [System.Windows.SystemParameters]::WorkArea
$script:groundTop = $workArea.Bottom - $window.Height - 8
$window.Left = $workArea.Right - $window.Width - 24
$window.Top = $script:groundTop

$script:paused = $false
$script:jumping = $false
$script:dragged = $false
$script:jumpSpeed = 0.0
$script:jumpOffset = 0.0
$script:waitTicks = 160
$script:blinkTicks = 0
$script:speechTicks = 0
$script:lastClickAt = [DateTime]::MinValue
$script:docked = $false
$script:dockSide = "right"
# The animation timer ticks every 16 ms, so these counts are durations.
# The pet used to dock 360 ticks (5.8s) after appearing and only 105 ticks
# (1.7s) after the pointer left it. At Windows sign-in nobody is touching the
# pet, so it shrank to the edge peek before the user ever saw it and looked
# like it had failed to start. Give it a visible dwell time instead.
$idleDockTicks = 1875          # 30s of no interaction before docking
$startupDockTicks = 3750       # 60s grace right after launch / sign-in
$pointerLeaveDockTicks = 938   # 15s after the pointer leaves the pet
$script:dockCountdown = $startupDockTicks
$script:allowClose = $false
$autoDockEnabled = $true      # Auto-dock to the circular peek; only a click restores it.
$expandedWidth = 172.0
$expandedHeight = 198.0
$peekWidth = 70.0
$peekHeight = 76.0
$edgeMargin = 6.0
$random = [System.Random]::new()

function Show-PetSpeech([string]$text, [int]$ticks = 115) {
  $speechText.Text = $text
  $speechBubble.Opacity = 1
  $script:speechTicks = $ticks
}

function Start-PetJump {
  if ($script:jumping) { return }
  $script:jumping = $true
  $script:jumpSpeed = -4.4
  $script:jumpOffset = 0.0
}

function Reset-DockCountdown([int]$ticks = $idleDockTicks) {
  if (-not $script:docked) { $script:dockCountdown = $ticks }
}

function Hide-PetAtEdge {
  if ($script:docked) { return }
  $area = [System.Windows.SystemParameters]::WorkArea
  $center = $window.Left + ($window.Width / 2)
  $script:dockSide = if ($center -lt ($area.Left + $area.Width / 2)) { "left" } else { "right" }
  $top = [Math]::Max($area.Top + $edgeMargin, [Math]::Min($area.Bottom - $peekHeight - $edgeMargin, $window.Top + 42))
  $script:docked = $true
  $script:jumping = $false
  $speechBubble.Visibility = [System.Windows.Visibility]::Collapsed
  $petRoot.Visibility = [System.Windows.Visibility]::Collapsed
  $petImage.Visibility = [System.Windows.Visibility]::Collapsed
  $schoolBadge.Visibility = [System.Windows.Visibility]::Collapsed
  $dockPeek.Visibility = [System.Windows.Visibility]::Visible
  $window.Width = $peekWidth
  $window.Height = $peekHeight
  $window.Left = if ($script:dockSide -eq "left") { $area.Left + $edgeMargin } else { $area.Right - $peekWidth - $edgeMargin }
  $window.Top = $top
}

function Show-FullPet {
  if (-not $script:docked) { Reset-DockCountdown; return }
  $area = [System.Windows.SystemParameters]::WorkArea
  $top = [Math]::Max($area.Top + $edgeMargin, [Math]::Min($area.Bottom - $expandedHeight - $edgeMargin, $window.Top - 42))
  $window.Width = $expandedWidth
  $window.Height = $expandedHeight
  $window.Left = if ($script:dockSide -eq "left") { $area.Left + $edgeMargin } else { $area.Right - $expandedWidth - $edgeMargin }
  $window.Top = $top
  $script:groundTop = $top
  $dockPeek.Visibility = [System.Windows.Visibility]::Collapsed
  $petImage.Visibility = [System.Windows.Visibility]::Visible
  $schoolBadge.Visibility = [System.Windows.Visibility]::Visible
  $speechBubble.Visibility = [System.Windows.Visibility]::Visible
  $script:docked = $false
  Reset-DockCountdown
  Show-PetSpeech "安全巡检中" 85
}

function Open-AuditWorkspace {
  $launcher = Join-Path $PSScriptRoot "open_security_audit.ps1"
  $pageUrl = "$serviceBaseUrl/security-layer.html"
  # /health answers in about 0.6s idle and slower under audit load, so a single
  # one-second probe used to classify a live backend as down and send the user
  # through the gateway-restart path and a failure dialog. Retry briefly first.
  $serviceReady = $false
  for ($probe = 1; $probe -le 3; $probe++) {
    try {
      $health = Invoke-WebRequest -UseBasicParsing -Uri "$serviceBaseUrl/health" -TimeoutSec 5
      if ($health.StatusCode -eq 200) { $serviceReady = $true; break }
    } catch { }
    if ($probe -lt 3) { Start-Sleep -Milliseconds 400 }
  }
  if ($serviceReady) {
    Start-Process $pageUrl
  } elseif (Test-Path -LiteralPath $launcher) {
    Start-Process -FilePath "powershell.exe" -ArgumentList @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "`"$launcher`"") -WindowStyle Hidden
  } else {
    Start-Process $pageUrl
  }
  Show-PetSpeech "正在打开审计平台" 150
}

$menu = [System.Windows.Controls.ContextMenu]::new()
$schoolItem = [System.Windows.Controls.MenuItem]::new()
$schoolItem.Header = "中国计量大学学生作品"
$schoolItem.IsEnabled = $false
$pauseItem = [System.Windows.Controls.MenuItem]::new()
$pauseItem.Header = "暂停动作"
$hideItem = [System.Windows.Controls.MenuItem]::new()
$hideItem.Header = "隐藏到屏幕边缘"
$homeItem = [System.Windows.Controls.MenuItem]::new()
$homeItem.Header = "回到屏幕底部"
$openItem = [System.Windows.Controls.MenuItem]::new()
$openItem.Header = "打开安全审计平台"
$exitItem = [System.Windows.Controls.MenuItem]::new()
$exitItem.Header = "彻底退出桌宠（安全防护继续运行）"
[void]$menu.Items.Add($schoolItem)
[void]$menu.Items.Add([System.Windows.Controls.Separator]::new())
[void]$menu.Items.Add($pauseItem)
[void]$menu.Items.Add($homeItem)
[void]$menu.Items.Add($hideItem)
[void]$menu.Items.Add([System.Windows.Controls.Separator]::new())
[void]$menu.Items.Add($openItem)
[void]$menu.Items.Add($exitItem)
$window.ContextMenu = $menu

$pauseItem.Add_Click({
  $script:paused = -not $script:paused
  $pauseItem.Header = if ($script:paused) { "继续动作" } else { "暂停动作" }
  Show-PetSpeech $(if ($script:paused) { "已暂停" } else { "继续安全巡检" })
})
$homeItem.Add_Click({
  Show-FullPet
  $script:groundTop = [System.Windows.SystemParameters]::WorkArea.Bottom - $window.Height - 8
  $window.Top = $script:groundTop
  Show-PetSpeech "回到工作区"
})
$hideItem.Add_Click({ Hide-PetAtEdge })
$openItem.Add_Click({ Open-AuditWorkspace })
$exitItem.Add_Click({ $script:allowClose = $true; $window.Close() })

$window.Add_MouseMove({ Reset-DockCountdown })
$window.Add_MouseLeave({ Reset-DockCountdown $pointerLeaveDockTicks })
$dockPeek.Add_MouseLeftButtonDown({
  param($sender, $eventArgs)
  Show-FullPet
  Reset-DockCountdown $startupDockTicks
  try { [void]$window.Activate() } catch { }
  $eventArgs.Handled = $true
})

$window.Add_MouseLeftButtonDown({
  param($sender, $eventArgs)
  # A docked pet must only expand on an intentional click. Pointer hover does
  # nothing, which keeps the edge peek from jumping out while the user works.
  if ($script:docked) {
    $script:lastClickAt = [DateTime]::MinValue
    Show-FullPet
    Reset-DockCountdown $startupDockTicks
    try { [void]$window.Activate() } catch { }
    $eventArgs.Handled = $true
    return
  }
  $now = [DateTime]::UtcNow
  $millisecondsSinceLastClick = ($now - $script:lastClickAt).TotalMilliseconds
  if ($millisecondsSinceLastClick -ge 80 -and $millisecondsSinceLastClick -le 650) {
    $script:lastClickAt = [DateTime]::MinValue
    Open-AuditWorkspace
    $eventArgs.Handled = $true
    return
  }
  $script:lastClickAt = $now
  Reset-DockCountdown
  $beforeLeft = $window.Left
  $beforeTop = $window.Top
  $script:dragged = $false
  $script:jumping = $false
  $script:jumpOffset = 0
  try { $window.DragMove() } catch { }
  $distance = [Math]::Abs($window.Left - $beforeLeft) + [Math]::Abs($window.Top - $beforeTop)
  if ($distance -gt 4) {
    $script:lastClickAt = [DateTime]::MinValue
    $script:dragged = $true
    $area = [System.Windows.SystemParameters]::WorkArea
    $window.Left = [Math]::Max($area.Left, [Math]::Min($area.Right - $window.Width, $window.Left))
    $window.Top = [Math]::Max($area.Top, [Math]::Min($area.Bottom - $window.Height, $window.Top))
    $script:groundTop = $window.Top
    Show-PetSpeech "放在这里"
  } else {
    Start-PetJump
    Show-PetSpeech "安全巡检中"
  }
})

$timer = [System.Windows.Threading.DispatcherTimer]::new()
$timer.Interval = [TimeSpan]::FromMilliseconds(16)
$timer.Add_Tick({
  # A second launch (Start menu, installer, or the console entry point) sets
  # this event instead of starting a duplicate pet. Checked here because the
  # tick already runs on the UI thread, so the window can be shown directly.
  if ($script:showRequest -and $script:showRequest.WaitOne(0)) {
    Show-FullPet
    Reset-DockCountdown $startupDockTicks
    try { [void]$window.Activate() } catch { }
  }
  if ($script:hideRequest -and $script:hideRequest.WaitOne(0)) {
    Hide-PetAtEdge
  }
  if ($autoDockEnabled -and -not $script:docked) {
    $script:dockCountdown--
    if ($script:dockCountdown -le 0 -and -not $menu.IsOpen) {
      Hide-PetAtEdge
    }
  }
  if (-not $script:docked -and -not $script:paused -and -not $script:jumping) {
    $script:waitTicks--
    if ($script:waitTicks -le 0) {
      Start-PetJump
      $script:waitTicks = $random.Next(270, 440)
      if ($random.NextDouble() -gt 0.6) { Show-PetSpeech "安全巡检中" 80 }
    }
  }

  if (-not $script:docked -and $script:jumping) {
    $script:jumpOffset += $script:jumpSpeed
    $script:jumpSpeed += 0.48
    if ($script:jumpOffset -ge 0) {
      $script:jumpOffset = 0
      $script:jumping = $false
    }
    $window.Top = $script:groundTop + $script:jumpOffset
  }

  $script:blinkTicks++
  if ($script:blinkTicks -eq 250) {
    $leftEye.Height = 1.5
    $rightEye.Height = 1.5
  } elseif ($script:blinkTicks -ge 260) {
    $leftEye.Height = 9
    $rightEye.Height = 9
    $script:blinkTicks = $random.Next(-80, 40)
  }

  if ($script:speechTicks -gt 0) {
    $script:speechTicks--
    if ($script:speechTicks -eq 0) { $speechBubble.Opacity = 0 }
  }
})

$window.Add_Closing({
  param($sender, $eventArgs)
  if (-not $script:allowClose) {
    $eventArgs.Cancel = $true
    Hide-PetAtEdge
  }
})

$window.Add_Closed({
  $timer.Stop()
  if ($script:showRequest) { $script:showRequest.Dispose(); $script:showRequest = $null }
  if ($script:hideRequest) { $script:hideRequest.Dispose(); $script:hideRequest = $null }
  if ($mutex) { $mutex.ReleaseMutex(); $mutex.Dispose() }
})

$timer.Start()
Show-PetSpeech "中国计量大学学生作品" 190
[void]$window.ShowDialog()
