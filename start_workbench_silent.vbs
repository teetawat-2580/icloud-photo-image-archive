' CloudVault Concierge — Silent Windows Launcher for Local Operator PC Workbench
' Starts `pythonw -m workbench.server` strictly on 127.0.0.1:8790 without showing a console window.

Option Explicit

Dim shell, fso, rootDir, envProc, pyCmd, launchCmd
Set shell = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")

rootDir = fso.GetParentFolderName(WScript.ScriptFullName)

Set envProc = shell.Environment("PROCESS")
envProc("PYTHONPATH") = rootDir
envProc("WORKBENCH_HOST") = "127.0.0.1"
envProc("WORKBENCH_PORT") = "8790"
If Len(envProc("STAGING_ROOT")) = 0 Then
    envProc("STAGING_ROOT") = "D:\MigrationJobs"
End If

shell.CurrentDirectory = rootDir

pyCmd = "pythonw.exe"
launchCmd = pyCmd & " -m workbench.server"

' Launch workbench server hidden (0 = SW_HIDE, False = do not wait)
On Error Resume Next
shell.Run launchCmd, 0, False
If Err.Number <> 0 Then
    Err.Clear
    shell.Run "python.exe -m workbench.server", 0, False
End If
On Error GoTo 0

WScript.Sleep 1800
shell.Run "http://127.0.0.1:8790", 1, False
