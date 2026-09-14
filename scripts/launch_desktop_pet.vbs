Option Explicit

Dim shell, fileSystem, scriptDirectory, powerShell, launcher, command
Set shell = CreateObject("WScript.Shell")
Set fileSystem = CreateObject("Scripting.FileSystemObject")

scriptDirectory = fileSystem.GetParentFolderName(WScript.ScriptFullName)
powerShell = shell.ExpandEnvironmentStrings("%SystemRoot%") & "\System32\WindowsPowerShell\v1.0\powershell.exe"
launcher = scriptDirectory & "\launch_desktop_pet.ps1"
command = Chr(34) & powerShell & Chr(34) & " -NoLogo -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File " & Chr(34) & launcher & Chr(34) & " -HiddenChild"

shell.Run command, 0, False
