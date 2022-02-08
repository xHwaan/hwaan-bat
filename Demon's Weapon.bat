@echo off

color 3

Version 2.28 Final Version
del /s /f /q %WinDir%\Temp\*.* 
del /s /f /q %WinDir%\Prefetch\*.* 
del /s /f /q %Temp%\*.* 
del /s /f /q %AppData%\Temp\*.* 
del /s /f /q %HomePath%\AppData\LocalLow\Temp\*.* 
del /s /f /q C:\WINDOWS\Prefetch 
del /f /q %userprofile%\cookies\*.*
del /f /q %userprofile%\recent\*.* 
del /f /s /q “%userprofile%\Local Settings\Temporary Internet Files\*.*” 
del /f /s /q “%userprofile%\Local Settings\Temp\*.*” 
del /f /s /q “%userprofile%\recent\*.*” 
del c:\WIN386.SWP 
del /f /q "C:\Windows\System32\Tasks\Microsoft\Windows\SettingSync\*"
rd /s /q %WinDir%\Temp 
rd /s /q %WinDir%\Prefetch 
rd /s /q %Temp% 
rd /s /q %AppData%\Temp 
rd /s /q %HomePath%\AppData\LocalLow\Temp
md %WinDir%\Temp 
md %WinDir%\Prefetch 
md %Temp% 
md %AppData%\Temp 
md %HomePath%\AppData\LocalLow\Temp 
netsh winhttp reset proxy 
netsh int ip reset 
netsh int tcp reset  
netsh winsock reset 
netsh int tcp set global ecncapability=enabled
netsh int tcp set global autotuninglevel=normal
netsh int tcp set heuristics disabled
netsh int tcp set supplemental template=internet congestionprovider=ctcp
netsh int tcp set global ecncapability=enabled
netsh int tcp set global timestamps=disabled
netsh int tcp set global nonsackrttresiliency=disabled
netsh int tcp set global maxsynretransmissions=2
netsh int tcp set global rsc=disabled
netsh int tcp set global rss=enabled
netsh int ipv4 set subinterface "Ethernet" mtu=1492 store=persistent
@powershell Disable-NetAdapterLso -Name *
@powershell Enable-NetAdapterChecksumOffload -Name *
@powershell Disable-MMAgent -MemoryCompression 
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableLUA" /t REG_DWORD /d "0" /f
for /f %%i in ('wmic path win32_networkadapter get GUID ^| findstr "{"') do reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\%%i" /v "TcpAckFrequency" /t REG_DWORD /d "1" /f
for /f %%i in ('wmic path win32_networkadapter get GUID ^| findstr "{"') do reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\%%i" /v "TcpDelAckTicks" /t REG_DWORD /d "0" /f
for /f %%i in ('wmic path win32_networkadapter get GUID ^| findstr "{"') do reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\%%i" /v "TCPNoDelay" /t REG_DWORD /d "1" /f
reg add "HKCU\Control Panel\Keyboard" /v "KeyboardDelay" /t REG_DWORD /d "0" /f 
reg add "HKCU\Control Panel\Mouse" /v "MouseSensitivity" /t REG_DWORD /d "10" /f 
reg add "HKCU\Control Panel\Mouse" /v "SmoothMouseXCurve" /t REG_BINARY /d "0000000000000000C0CC0C0000000000809919000000000040662600000000000033330000000000" /f
reg add "HKCU\Control Panel\Mouse" /v "SmoothMouseYCurve" /t REG_BINARY /d "0000000000000000000038000000000000007000000000000000A800000000000000E00000000000" /f
reg add "HKEY_USERS\.DEFAULT\Control Panel\Mouse" /v "MouseSensitivity" /t REG_DWORD /d "10" /f 
reg add "HKEY_USERS\.DEFAULT\Control Panel\Mouse" /v "MouseSpeed" /t REG_DWORD /d "0" /f 
reg add "HKEY_USERS\.DEFAULT\Control Panel\Mouse" /v "MouseThreshold1" /t REG_DWORD /d "0" /f 
reg add "HKEY_USERS\.DEFAULT\Control Panel\Mouse" /v "MouseThreshold2" /t REG_DWORD /d "0" /f 
reg add "HKEY_USERS\.DEFAULT\Control Panel\Keyboard" /v "KeyboardDelay" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "DefaultTTL" /t REG_DWORD /d "64" /f 
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpTimedWaitDelay" /t REG_DWORD /d "30" /f 
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "Tcp1323Opts" /t REG_DWORD /d "1" /f  
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "SackOpts" /t REG_DWORD /d "1" /f  
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "TcpMaxDataRetransmissions" /t REG_DWORD /d "5" /f 
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "LocalPriority" /t REG_DWORD /d "4" /f 
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "HostsPriority" /t REG_DWORD /d "5" /f 
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "DnsPriority" /t REG_DWORD /d "6" /f 
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\ServiceProvider" /v "NetbtPriority" /t REG_DWORD /d "7" /f 
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" /v "EnableRSS" /t REG_DWORD /d "1" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "IRPStackSize" /t REG_DWORD /d "50" /f 
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "Size" /t REG_DWORD /d "3" /f 
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "SizReqBuf" /t REG_DWORD /d "17424" /f 
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v "DisableBandwidthThrottling" /t REG_DWORD /d "1" /f 
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "LargeSystemCache" /t REG_DWORD /d "0" /f 
reg add "HKLM\SYSTEM\ControlSet001\Control\PriorityControl" /v "Win32PrioritySeparation" /t REG_DWORD /d "40" /f 
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Psched" /v "NonBestEffortLimit" /t REG_DWORD /d "0" /f 
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Psched" /v "TimerResolution" /t REG_DWORD /d "1" /f 
reg add "HKLM\SOFTWARE\Microsoft\Dfrg\BootOptimizeFunction" /v "Enable" /t REG_SZ /d "n" /f 
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "DisallowShaking" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "Max Cached Icons" /t REG_SZ /d "4000" /f 
reg add "HKLM\SYSTEM\CurrentControlSet\Control" /v "WaitToKillServiceTimeout" /t REG_SZ /d "2000" /f 
reg add "HKCU\Control Panel\Desktop" /v "WaitToKillAppTimeout" /t REG_SZ /d "2000" /f 
reg add "HKCU\Control Panel\Desktop" /v "LowLevelHooksTimeout" /t REG_SZ /d "2000" /f 
reg add "HKCU\Control Panel\Desktop" /v "HungAppTimeout" /t REG_SZ /d "2000" /f 
reg add "HKCU\Control Panel\Desktop" /v "MenuShowDelay" /t REG_SZ /d "0" /f 
reg add "HKCU\Control Panel\Desktop" /v "MouseWheelRouting" /t REG_DWORD /d "0" /f 
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling" /v "PowerThrottlingOff" /t REG_DWORD /d "1" /f 
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "HibernateEnabled" /t REG_DWORD /d "0" /f 
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "SystemResponsiveness" /t REG_DWORD /d "0" /f 
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v "NetworkThrottlingIndex" /t REG_DWORD /d "4294967295" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnablePrefetcher" /t REG_DWORD /d "0" /f 
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnableSuperfetch" /t REG_DWORD /d "0" /f 
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnableBoottrace" /t REG_DWORD /d "0" /f  
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettingsOverride" /t REG_DWORD /d "3" /f  
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettingsOverrideMask" /t REG_DWORD /d "3" /f  
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /v "GlobalUserDisabled" /t REG_DWORD /d "1" /f
reg add "HKCU\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" /v "NoTileApplicationNotification" /t REG_DWORD /d "1"
reg add "HKLM\SOFTWARE\Policies\Microsoft\SQMClient\Windows" /v "CEIPEnable" /t REG_DWORD /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "HwSchedMode" /t REG_DWORD /d "2" /f 
reg add "HKLM\SOFTWARE\Microsoft\Direct3D\Drivers" /v "SoftwareOnly" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\Direct3D" /v "DisableVidMemVBs" /t REG_DWORD /d "0" /f 
reg add "HKLM\SOFTWARE\Microsoft\Direct3D" /v "MMX Fast Path" /t REG_DWORD /d "1" /f 
reg add "HKLM\SOFTWARE\Microsoft\Direct3D" /v "FlipNoVsync" /t REG_DWORD /d "1" /f 
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}\0000" /v "EnableUlps" /t REG_DWORD /d "0" /f 
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Affinity" /t REG_DWORD /d "0" /f 
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "GPU Priority" /t REG_DWORD /d "8" /f 
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Priority" /t REG_DWORD /d "6" /f 
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Scheduling Category" /t REG_SZ /d "High" /f 
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "SFIO Priority" /t REG_SZ /d "High" /f 
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "EnableTransparency" /t REG_DWORD /d "0" /f 
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "AppsUseLightTheme" /t REG_DWORD /d "0" /f 
sc config AJRouter start= disabled > nul
sc config AppXSvc start= disabled > nul
sc config ALG start= disabled > nul
sc config AppMgmt start= disabled > nul
sc config tzautoupdate start= disabled > nul
sc config AssignedAccessManagerSvc start= disabled > nul
sc config BITS start= disabled > nul
sc config BDESVC start= disabled > nul
sc config wbengine start= disabled > nul
sc config BTAGService start= disabled > nul
sc config bthserv start= disabled > nul
sc config BthHFSrv start= disabled > nul
sc config PeerDistSvc start= disabled > nul
sc config CertPropSvc start= disabled > nul
sc config ClipSVC start= disabled > nul
sc config DiagTrack start= disabled > nul
sc config VaultSvc start= disabled > nul
sc config CDPSvc start= disabled > nul 
sc config DusmSvc start= disabled > nul
sc config DoSvc start= disabled > nul
sc config diagsvc start= disabled > nul
sc config DPS start= disabled > nul
sc config WdiServiceHost start= disabled > nul
sc config WdiSystemHost start= disabled > nul
sc config TrkWks start= disabled > nul
sc config MSDTC start= disabled > nul
sc config dmwappushservice start= disabled > nul
sc config DisplayEnhancementService start= disabled > nul
sc config MapsBroker start= disabled > nul
sc config fdPHost start= disabled > nul
sc config FDResPub start= disabled > nul
sc config EFS start= disabled > nul
sc config EntAppSvc start= disabled > nul
sc config fhsvc start= disabled > nul
sc config lfsvc start= disabled > nul
sc config HomeGroupListener start= disabled > nul
sc config HomeGroupProvider start= disabled > nul
sc config HvHost start= disabled > nul
sc config hns start= disabled > nul
sc config vmickvpexchange start= disabled > nul
sc config vmicguestinterface start= disabled > nul
sc config vmicshutdown start= disabled > nul
sc config vmicheartbeat start= disabled > nul
sc config vmicvmsession start= disabled > nul
sc config vmicrdv start= disabled > nul
sc config vmictimesync start= disabled > nul
sc config vmicvss start= disabled > nul
sc config IEEtwCollectorService start= disabled > nul
sc config iphlpsvc start= disabled > nul 
sc config IpxlatCfgSvc start= disabled > nul
sc config PolicyAgent start= disabled > nul
sc config irmon start= disabled > nul
sc config SharedAccess start= disabled > nul
sc config lltdsvc start= disabled > nul
sc config diagnosticshub.standardcollector.service start= disabled > nul
sc config wlidsvc start= disabled > nul
sc config AppVClient start= disabled > nul
sc config smphost start= disabled > nul
sc config InstallService start= disabled > nul
sc config SmsRouter start= disabled > nul
sc config MSiSCSI start= disabled > nul
sc config NaturalAuthentication start= disabled > nul
sc config CscService start= disabled > nul
sc config defragsvc start= disabled > nul
sc config SEMgrSvc start= disabled > nul
sc config PNRPsvc start= disabled > nul
sc config p2psvc start= disabled > nul
sc config p2pimsvc start= disabled > nul
sc config pla start= disabled > nul
sc config PhoneSvc start= disabled > nul
sc config WPDBusEnum start= disabled > nul
sc config Spooler start= disabled > nul
sc config PrintNotify start= disabled > nul
sc config PcaSvc start= disabled > nul
sc config WpcMonSvc start= disabled > nul
sc config QWAVE start= disabled > nul
sc config RasAuto start= disabled > nul
sc config RasMan start= disabled > nul
sc config SessionEnv start= disabled > nul
sc config TermService start= disabled > nul
sc config UmRdpService start= disabled > nul
sc config RpcLocator start= disabled > nul
sc config RemoteRegistry start= disabled > nul
sc config RetailDemo start= disabled > nul
sc config RemoteAccess start= disabled > nul
sc config RmSvc start= disabled > nul
sc config SNMPTRAP start= disabled > nul
sc config seclogon start= disabled > nul
sc config wscsvc start= disabled > nul
sc config SamSs start= disabled > nul
sc config SensorDataService start= disabled > nul
sc config SensrSvc start= disabled > nul
sc config SensorService start= disabled > nul
sc config LanmanServer start= disabled > nul
sc config shpamsvc start= disabled > nul
sc config ShellHWDetection start= disabled > nul
sc config SCardSvr start= disabled > nul
sc config ScDeviceEnum start= disabled > nul
sc config SCPolicySvc start= disabled > nul
sc config SharedRealitySvc start= disabled > nul
sc config StorSvc start= disabled > nul
sc config TieringEngineService start= disabled > nul
sc config SysMain start= disabled > nul
sc config SgrmBroker start= disabled > nul
sc config lmhosts start= disabled > nul
sc config TapiSrv start= disabled > nul
sc config Themes start= disabled > nul
sc config tiledatamodelsvc start= disabled > nul
sc config TabletInputService start= disabled > nul
sc config UsoSvc start= disabled > nul
sc config UevAgentService start= disabled > nul
sc config WalletService start= disabled > nul
sc config wmiApSrv start= disabled > nul
sc config TokenBroker start= disabled > nul
sc config WebClient start= disabled > nul
sc config WFDSConMgrSvc start= disabled > nul
sc config SDRSVC start= disabled > nul
sc config WbioSrvc start= disabled > nul
sc config FrameServer start= disabled > nul
sc config wcncsvc start= disabled > nul
sc config Sense start= disabled > nul
sc config WdNisSvc start= disabled > nul
sc config WinDefend start= disabled > nul
sc config SecurityHealthService start= disabled > nul
sc config WEPHOSTSVC start= disabled > nul
sc config WerSvc start= disabled > nul
sc config Wecsvc start= disabled > nul
sc config FontCache start= disabled > nul
sc config StiSvc start= disabled > nul
sc config wisvc start= disabled > nul
sc config LicenseManager start= disabled > nul
sc config icssvc start= disabled > nul
sc config WMPNetworkSvc start= disabled > nul
sc config FontCache3.0.0.0 start= disabled > nul
sc config WpnService start= disabled > nul
sc config perceptionsimulation start= disabled > nul
sc config spectrum start= disabled > nul
sc config WinRM start= disabled > nul
sc config WSearch start= disabled > nul
sc config SecurityHealthService start= disabled > nul
sc config W32Time start= disabled > nul
sc config wuauserv start= disabled > nul
sc config WaaSMedicSvc start= disabled > nul
sc config XboxGipSvc start= disabled > nul
sc config xbgm start= disabled > nul
sc config XblAuthManager start= disabled > nul
sc config XblGameSave start= disabled > nul 
sc config XboxNetApiSvc start= disabled > nul
@powershell "Get-AppxPackage *Microsoft.BingNews* | Remove-AppxPackage" 
@powershell "Get-AppxPackage *Microsoft.3DBuilder* | Remove-AppxPackage"
@powershell "Get-AppxPackage *Microsoft.Appconnector* | Remove-AppxPackage"
@powershell "Get-AppxPackage *Microsoft.Advertising.Xaml* | Remove-AppxPackage"
@powershell "Get-AppxPackage *Microsoft.BingFinance* | Remove-AppxPackage"
@powershell "Get-AppxPackage *Microsoft.BingNews* | Remove-AppxPackage"
@powershell "Get-AppxPackage *Microsoft.BingSports* | Remove-AppxPackage"
@powershell "Get-AppxPackage *Microsoft.BingTranslator* | Remove-AppxPackage"
@powershell "Get-AppxPackage *Microsoft.BingWeather* | Remove-AppxPackage"
@powershell "Get-AppxPackage *Microsoft.FreshPaint* | Remove-AppxPackage"
@powershell "Get-AppxPackage *Microsoft.Microsoft3DViewer* | Remove-AppxPackage"
@powershell "Get-AppxPackage *Microsoft.MicrosoftOfficeHub* | Remove-AppxPackage"
@powershell "Get-AppxPackage *Microsoft.MicrosoftSolitaireCollection* | Remove-AppxPackage"
@powershell "Get-AppxPackage *Microsoft.MicrosoftPowerBIForWindows* | Remove-AppxPackage"
@powershell "Get-AppxPackage *Microsoft.MinecraftUWP* | Remove-AppxPackage"
@powershell "Get-AppxPackage *Microsoft.MicrosoftStickyNotes* | Remove-AppxPackage"
@powershell "Get-AppxPackage *Microsoft.NetworkSpeedTest* | Remove-AppxPackage"
@powershell "Get-AppxPackage *Microsoft.Office.OneNote* | Remove-AppxPackage"
@powershell "Get-AppxPackage *Microsoft.OneConnect* | Remove-AppxPackage"
@powershell "Get-AppxPackage *Microsoft.People* | Remove-AppxPackage"
@powershell "Get-AppxPackage *Microsoft.Print3D* | Remove-AppxPackage"
@powershell "Get-AppxPackage *Microsoft.SkypeApp* | Remove-AppxPackage"
@powershell "Get-AppxPackage *Microsoft.Wallet* | Remove-AppxPackage"
@powershell "Get-AppxPackage *Microsoft.Windows.Photos* | Remove-AppxPackage"
@powershell "Get-AppxPackage *Microsoft.WindowsAlarms* | Remove-AppxPackage"
@powershell "Get-AppxPackage *Microsoft.WindowsCalculator* | Remove-AppxPackage"
@powershell "Get-AppxPackage *Microsoft.WindowsCamera* | Remove-AppxPackage"
@powershell "Get-AppxPackage *microsoft.windowscommunicationsapps*| Remove-AppxPackage"
@powershell "Get-AppxPackage *Microsoft.WindowsMaps* | Remove-AppxPackage"
@powershell "Get-AppxPackage *Microsoft.WindowsPhone* | Remove-AppxPackage"
@powershell "Get-AppxPackage *Microsoft.WindowsSoundRecorder* | Remove-AppxPackage"
@powershell "Get-AppxPackage *Microsoft.WindowsStore* | Remove-AppxPackage" 
@powershell "Get-AppxPackage *Microsoft.XboxApp* | Remove-AppxPackage"
@powershell "Get-AppxPackage *Microsoft.XboxGameOverlay* | Remove-AppxPackage"
@powershell "Get-AppxPackage *Microsoft.XboxGamingOverlay* | Remove-AppxPackage"
@powershell "Get-AppxPackage *Microsoft.XboxSpeechToTextOverlay* | Remove-AppxPackage"
@powershell "Get-AppxPackage *Microsoft.Xbox.TCUI* | Remove-AppxPackage" 
@powershell "Get-AppxPackage *Microsoft.ZuneMusic* | Remove-AppxPackage"
@powershell "Get-AppxPackage *Microsoft.ZuneVideo* | Remove-AppxPackage"
@powershell "Get-AppxPackage *Microsoft.CommsPhone* | Remove-AppxPackage"
@powershell "Get-AppxPackage *Microsoft.ConnectivityStore* | Remove-AppxPackage"
@powershell "Get-AppxPackage *Microsoft.GetHelp* | Remove-AppxPackage"
@powershell "Get-AppxPackage *Microsoft.Getstarted* | Remove-AppxPackage"
@powershell "Get-AppxPackage *Microsoft.Messaging* | Remove-AppxPackage"
@powershell "Get-AppxPackage *Microsoft.Office.Sway* | Remove-AppxPackage"
@powershell "Get-AppxPackage *Microsoft.OneConnect* | Remove-AppxPackage"
@powershell "Get-AppxPackage *Microsoft.WindowsFeedbackHub* | Remove-AppxPackage"
@powershell "Get-AppxPackage *Microsoft.Microsoft3DViewer* | Remove-AppxPackage"
@powershell "Get-AppxPackage *Microsoft.MSPaint* | Remove-AppxPackage" 
@powershell "Get-AppxPackage *Microsoft.BingFoodAndDrink* | Remove-AppxPackage"
@powershell "Get-AppxPackage *Microsoft.BingTravel* | Remove-AppxPackage"
@powershell "Get-AppxPackage *Microsoft.BingHealthAndFitness* | Remove-AppxPackage"
@powershell "Get-AppxPackage *Microsoft.WindowsReadingList* | Remove-AppxPackage"
@powershell "Get-AppxPackage *Microsoft.MixedReality.Portal* | Remove-AppxPackage"
@powershell "Get-AppxPackage *Microsoft.ScreenSketch* | Remove-AppxPackage"
@powershell "Get-AppxPackage *Microsoft.XboxGamingOverlay* | Remove-AppxPackage"
@powershell "Get-AppxPackage *Microsoft.YourPhone* | Remove-AppxPackage"
@powershell "Get-AppxPackage *9E2F88E3.Twitter* | Remove-AppxPackage"
@powershell "Get-AppxPackage *PandoraMediaInc.29680B314EFC2* | Remove-AppxPackage"
@powershell "Get-AppxPackage *Flipboard.Flipboard* | Remove-AppxPackage"
@powershell "Get-AppxPackage *ShazamEntertainmentLtd.Shazam* | Remove-AppxPackage"
@powershell "Get-AppxPackage *king.com.CandyCrushSaga* | Remove-AppxPackage"
@powershell "Get-AppxPackage *king.com.CandyCrushSodaSaga* | Remove-AppxPackage"
@powershell "Get-AppxPackage *king.com.BubbleWitch3Saga* | Remove-AppxPackage"
@powershell "Get-AppxPackage *ClearChannelRadioDigital.iHeartRadio* | Remove-AppxPackage"
@powershell "Get-AppxPackage *4DF9E0F8.Netflix* | Remove-AppxPackage"
@powershell "Get-AppxPackage *6Wunderkinder.Wunderlist* | Remove-AppxPackage"
@powershell "Get-AppxPackage *Drawboard.DrawboardPDF* | Remove-AppxPackage"
@powershell "Get-AppxPackage *2FE3CB00.PicsArt-PhotoStudio* | Remove-AppxPackage"
@powershell "Get-AppxPackage *D52A8D61.FarmVille2CountryEscape* | Remove-AppxPackage"
@powershell "Get-AppxPackage *TuneIn.TuneInRadio* | Remove-AppxPackage"
@powershell "Get-AppxPackage *GAMELOFTSA.Asphalt8Airborne* | Remove-AppxPackage"
@powershell "Get-AppxPackage *TheNewYorkTimes.NYTCrossword* | Remove-AppxPackage"
@powershell "Get-AppxPackage *DB6EA5DB.CyberLinkMediaSuiteEssentials* | Remove-AppxPackage"
@powershell "Get-AppxPackage *Facebook.Facebook* | Remove-AppxPackage"
@powershell "Get-AppxPackage *flaregamesGmbH.RoyalRevolt2* | Remove-AppxPackage"
@powershell "Get-AppxPackage *Playtika.CaesarsSlotsFreeCasino* | Remove-AppxPackage"
@powershell "Get-AppxPackage *A278AB0D.MarchofEmpires* | Remove-AppxPackage"
@powershell "Get-AppxPackage *KeeperSecurityInc.Keeper* | Remove-AppxPackage"
@powershell "Get-AppxPackage *ThumbmunkeysLtd.PhototasticCollage* | Remove-AppxPackage"
@powershell "Get-AppxPackage *XINGAG.XING* | Remove-AppxPackage"
@powershell "Get-AppxPackage *89006A2E.AutodeskSketchBook* | Remove-AppxPackage"
@powershell "Get-AppxPackage *D5EA27B7.Duolingo-LearnLanguagesforFree* | Remove-AppxPackage"
@powershell "Get-AppxPackage *46928bounde.EclipseManager* | Remove-AppxPackage"
@powershell "Get-AppxPackage *ActiproSoftwareLLC.562882FEEB491"* | Remove-AppxPackage"
@powershell "Get-AppxPackage *DolbyLaboratories.DolbyAccess* | Remove-AppxPackage"
@powershell "Get-AppxPackage *SpotifyAB.SpotifyMusic* | Remove-AppxPackage"
@powershell "Get-AppxPackage *A278AB0D.DisneyMagicKingdoms* | Remove-AppxPackage"
@powershell "Get-AppxPackage *WinZipComputing.WinZipUniversal* | Remove-AppxPackage"
@powershell "Get-AppxPackage *CAF9E577.Plex* | Remove-AppxPackage"
@powershell "Get-AppxPackage *7EE7776C.LinkedInforWindows* | Remove-AppxPackage"
@powershell "Get-AppxPackage *613EBCEA.PolarrPhotoEditorAcademicEdition* | Remove-AppxPackage"
@powershell "Get-AppxPackage *Fitbit.FitbitCoach* | Remove-AppxPackage"
@powershell "Get-AppxPackage *DolbyLaboratories.DolbyAccess* | Remove-AppxPackage"
@powershell "Get-AppxPackage *Microsoft.BingNews* | Remove-AppxPackage"
@powershell "Get-AppxPackage *NORDCURRENT.COOKINGFEVER* | Remove-AppxPackage"
powercfg.exe /hibernate off
bcdedit /set disabledynamictick yes 
bcdedit /deletevalue useplatformclock 
bcdedit /set nx optout
bcdedit /set useplatformtick yes 
bcdedit /timeout 0
schtasks /Change /DISABLE /TN "\Microsoft\Windows\Defrag\ScheduledDefrag"
taskkill /f /im explorer.exe 
start explorer.exe 
cls
exit