#ifndef PackageRoot
  #error PackageRoot must be provided by the build script
#endif
#ifndef OutputDir
  #error OutputDir must be provided by the build script
#endif
#ifndef AppVersion
  #error AppVersion must be provided by the build script
#endif

[Setup]
AppId={{64A869F7-3469-43A5-A8F2-EAE7E0D51C1E}
AppName=AgentMeter-Gov
AppVersion={#AppVersion}
AppPublisher=中国计量大学学生团队
DefaultDirName={localappdata}\AgentMeter-Gov\Installer
DefaultGroupName=AgentMeter-Gov
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
ArchitecturesAllowed=x64compatible
OutputDir={#OutputDir}
OutputBaseFilename=AgentMeter-Gov-Setup-{#AppVersion}
SetupIconFile={#PackageRoot}\payload\backend\_internal\frontend\assets\desktop-pet-audit-fox.ico
UninstallDisplayIcon={app}\desktop-pet-audit-fox.ico
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
CloseApplications=no
RestartApplications=no
DisableWelcomePage=no
SetupLogging=yes

[Files]
Source: "{#PackageRoot}\*"; DestDir: "{tmp}\AgentMeterGovPackage"; Flags: recursesubdirs createallsubdirs dontcopy noencryption
Source: "{#PackageRoot}\installer\uninstall.ps1"; DestDir: "{app}"; DestName: "uninstall-agentmeter.ps1"; Flags: ignoreversion
Source: "{#PackageRoot}\payload\backend\_internal\frontend\assets\desktop-pet-audit-fox.ico"; DestDir: "{app}"; DestName: "desktop-pet-audit-fox.ico"; Flags: ignoreversion

[UninstallRun]
Filename: "{sys}\WindowsPowerShell\v1.0\powershell.exe"; Parameters: "-NoLogo -NoProfile -ExecutionPolicy Bypass -File ""{app}\uninstall-agentmeter.ps1"""; Flags: runhidden waituntilterminated; RunOnceId: "AgentMeterGovUninstall"

[Run]
Filename: "{sys}\wscript.exe"; Parameters: """{localappdata}\AgentMeter-Gov\current\desktop\launch_desktop_pet.vbs"""; Description: "启动 AgentMeter-Gov 桌宠"; Flags: postinstall nowait skipifsilent runhidden

[Code]
function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  ResultCode: Integer;
  PowerShellPath: String;
  InstallScript: String;
  ServiceBaseUrl: String;
  InstallArguments: String;
begin
  Result := '';
  NeedsRestart := False;
  ExtractTemporaryFiles('{tmp}\AgentMeterGovPackage\*');
  PowerShellPath := ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe');
  InstallScript := ExpandConstant('{tmp}\AgentMeterGovPackage\installer\install.ps1');
  ServiceBaseUrl := ExpandConstant('{param:SERVICEBASEURL|http://127.0.0.1:8765}');
  InstallArguments := '-NoLogo -NoProfile -ExecutionPolicy Bypass -File "' + InstallScript +
    '" -ServiceBaseUrl "' + ServiceBaseUrl + '"';
  { Interactive setup launches the pet from [Run] after the Finish page. Silent
    setup skips [Run], so the core installer must launch the pet itself. }
  if not WizardSilent then
    InstallArguments := InstallArguments + ' -SkipDesktopPetLaunch';
  WizardForm.StatusLabel.Caption := '正在检测 OpenClaw 并安装 AgentMeter-Gov...';
  if (not Exec(PowerShellPath, InstallArguments,
    '', SW_HIDE, ewWaitUntilTerminated, ResultCode)) or (ResultCode <> 0) then
  begin
    Result := Format('AgentMeter-Gov 安装核心执行失败（退出码 %d）。安装器已保留诊断备份；请保留错误窗口或日志。', [ResultCode]);
  end;
end;

procedure CurPageChanged(CurPageID: Integer);
begin
  if CurPageID = wpFinished then
  begin
    WizardForm.FinishedLabel.Caption :=
      'AgentMeter-Gov 已安装或升级完成。桌宠退出后，OpenClaw 安全防护仍会继续运行。';
  end;
end;
