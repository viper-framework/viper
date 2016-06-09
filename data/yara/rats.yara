
rule Arcom
{
    meta:
        author = " Kevin Breen <kevin@techanarchy.net>"
        date = "2014/04"
        ref = "http://malwareconfig.com/stats/Arcom"
        family = "arcom"
        tags = "rat, arcom"

    strings:
        $a1 = "CVu3388fnek3W(3ij3fkp0930di"
        $a2 = "ZINGAWI2"
        $a3 = "clWebLightGoldenrodYellow"
        $a4 = "Ancestor for '%s' not found" wide
        $a5 = "Control-C hit" wide
        $a6 = {A3 24 25 21}

    condition:
        all of them
}

rule adWind
{
    meta:
        author = " Kevin Breen <kevin@techanarchy.net>"
        date = "2014/04"
        ref = "http://malwareconfig.com/stats/adWind"
        family = "adwind"
        tags = "rat, adwind"

    strings:
        $meta = "META-INF"
        $conf = "config.xml"
        $a = "Adwind.class"
        $b = "Principal.adwind"

    condition:
        all of them
}

rule Adzok
{
    meta:
        author = " Kevin Breen <kevin@techanarchy.net>"
        Description = "Adzok Rat"
        Versions = "Free 1.0.0.3,"
        date = "2015/05"
        ref = "http://malwareconfig.com/stats/Adzok"
        maltype = "Remote Access Trojan"
        filetype = "jar"
        family = "adzok"
        tags = "rat, adzok"

    strings:
        $a1 = "config.xmlPK"
        $a2 = "key.classPK"
        $a3 = "svd$1.classPK"
        $a4 = "svd$2.classPK"
    $a5 = "Mensaje.classPK"
        $a6 = "inic$ShutdownHook.class"
        $a7 = "Uninstall.jarPK"
        $a8 = "resources/icono.pngPK"
        
    condition:
    7 of ($a*)
}

rule Ap0calypse
{
    meta:
        author = " Kevin Breen <kevin@techanarchy.net>"
        date = "2014/04"
        ref = "http://malwareconfig.com/stats/Ap0calypse"
        family = "ap0calypse"
        tags = "rat, apocalypse"

    strings:
        $a = "Ap0calypse"
        $b = "Sifre"
        $c = "MsgGoster"
        $d = "Baslik"
        $e = "Dosyalars"
        $f = "Injecsiyon"

    condition:
        all of them
}

rule Albertino
{
    meta:
        author = " Kevin Breen <kevin@techanarchy.net>"
        date = "2014/04"
        ref = "http://malwareconfig.com/stats/AAR"
        family = "albertino"
        tags = "rat, albertino"

    strings:
        $a = "Hashtable"
        $b = "get_IsDisposed"
        $c = "TripleDES"
        $d = "testmemory.FRMMain.resources"
        $e = "$this.Icon" wide
        $f = "{11111-22222-20001-00001}" wide
        $g = "@@@@@@@@@@@"

    condition:
        all of them
}

rule AlienSpy
{
    meta:
        author = " Kevin Breen <kevin@techanarchy.net>"
        date = "2015/03"
        ref = "http://malwareconfig.com/stats/AlienSpy"
        maltype = "Remote Access Trojan"
        filetype = "jar"
        family = "alienspy"
        tags = "rat, alienspy"

    strings:
        $a1 = "Main.classPK"
        $a2 = "MANIFEST.MFPK"
        $a3 = "plugins/Server.classPK"
        $a4 = "META-INF/MANIFEST.MF"
        $a5 = "ID"
        
        $b1 = "config.xml"
        $b2 = "options/PK"
        $b3 = "plugins/PK"
        $b4 = "util/PK"
        $b5 = "util/OSHelper/PK"
        $b6 = "Start.class"
        $b7 = "AlienSpy"
    condition:
        all of ($a*) or all of ($b*)
}

rule Bandook
{

    meta:
        author = " Kevin Breen <kevin@techanarchy.net>"
        date = "2014/04"
        ref = "http://malwareconfig.com/stats/Bandook"
        maltype = "Remote Access Trojan"
        family = "bandook"
        tags = "rat, bandook"

    strings:
            $a = "aaaaaa1|"
            $b = "aaaaaa2|"
            $c = "aaaaaa3|"
            $d = "aaaaaa4|"
            $e = "aaaaaa5|"
            $f = "%s%d.exe"
            $g = "astalavista"
            $h = "givemecache"
            $i = "%s\\system32\\drivers\\blogs\\*"
            $j = "bndk13me"

    condition:
            all of them
}

rule BlackNix
{
    meta:
        author = " Kevin Breen <kevin@techanarchy.net>"
        date = "2014/04"
        ref = "http://malwareconfig.com/stats/BlackNix"
        family = "blacknix"
        tags = "rat, blacknix"

    strings:
        $a1 = "SETTINGS" wide
        $a2 = "Mark Adler"
        $a3 = "Random-Number-Here"
        $a4 = "RemoteShell"
        $a5 = "SystemInfo"


    condition:
        all of them
}

rule Bozok
{
    meta:
        author = " Kevin Breen <kevin@techanarchy.net>"
        date = "2014/04"
        ref = "http://malwareconfig.com/stats/Bozok"
        family = "bozok"
        tags = "rat, bozok"

    strings:
        $a = "getVer" nocase
        $b = "StartVNC" nocase
        $c = "SendCamList" nocase
        $d = "untPlugin" nocase
        $e = "gethostbyname" nocase

    condition:
        all of them
}

rule BlueBanana
{
    meta:
        author = " Kevin Breen <kevin@techanarchy.net>"
        date = "2014/04"
        ref = "http://malwareconfig.com/stats/BlueBanana"
        maltype = "Remote Access Trojan"
        filetype = "Java"
        family = "bluebanana"
        tags = "rat, bluebanane"

    strings:
        $meta = "META-INF"
        $conf = "config.txt"
        $a = "a/a/a/a/f.class"
        $b = "a/a/a/a/l.class"
        $c = "a/a/a/b/q.class"
        $d = "a/a/a/b/v.class"


    condition:
        all of them
}

rule BlackShades
{
    meta:
        author = "Brian Wallace (@botnet_hunter)"
        date = "2014/04"
        ref = "http://malwareconfig.com/stats/PoisonIvy"
        ref = "http://blog.cylance.com/a-study-in-bots-blackshades-net"
        family = "blackshades"
        tags = "rat blackshades"

    strings:
        $string1 = "bss_server"
        $string2 = "txtChat"
        $string3 = "UDPFlood"
    condition:
        all of them
}

rule ClientMesh
{
    meta:
        author = "Kevin Breen <kevin@techanarchy.net>"
        date = "2014/06"
        ref = "http://malwareconfig.com/stats/ClientMesh"
        family = "clientmesh"
        tags = "rat, clientmesh"

    strings:
        $string1 = "machinedetails"
        $string2 = "MySettings"
        $string3 = "sendftppasswords"
        $string4 = "sendbrowserpasswords"
        $string5 = "arma2keyMass"
        $string6 = "keylogger"
        $conf = {00 00 00 00 00 00 00 00 00 7E}

    condition:
        all of them
}

rule Crimson
{
    meta:
        author = " Kevin Breen <kevin@techanarchy.net>"
        Description = "Crimson Rat"
        date = "2015/05"
        ref = "http://malwareconfig.com/stats/Crimson"
        maltype = "Remote Access Trojan"
        filetype = "jar"
        family = "crimson"
        tags = "rat, crimson"

    strings:
        $a1 = "com/crimson/PK"
        $a2 = "com/crimson/bootstrapJar/PK"
        $a3 = "com/crimson/permaJarMulti/PermaJarReporter$1.classPK"
        $a4 = "com/crimson/universal/containers/KeyloggerLog.classPK"
        $a5 = "com/crimson/universal/UploadTransfer.classPK"
        
    condition:
        all of ($a*)
}

rule CyberGate
{

    meta:
        author = " Kevin Breen <kevin@techanarchy.net>"
        date = "2014/04"
        ref = "http://malwareconfig.com/stats/CyberGate"
        maltype = "Remote Access Trojan"
        filetype = "exe"
        family = "cybergate"
        tags = "rat, cybergate"

    strings:
        $string1 = {23 23 23 23 40 23 23 23 23 E8 EE E9 F9 23 23 23 23 40 23 23 23 23}
        $string2 = {23 23 23 23 40 23 23 23 23 FA FD F0 EF F9 23 23 23 23 40 23 23 23 23}
        $string3 = "EditSvr"
        $string4 = "TLoader"
        $string5 = "Stroks"
        $string6 = "####@####"
        $res1 = "XX-XX-XX-XX"
        $res2 = "CG-CG-CG-CG"

    condition:
        all of ($string*) and any of ($res*)
}

rule DarkComet
{
    meta:
        author = " Kevin Breen <kevin@techanarchy.net>"
        date = "2014/04"
        ref = "http://malwareconfig.com/stats/DarkComet"
        family = "darkcomet"
        tags = "rat, darkcomet"

    strings:
        // Versions 2x
        $a1 = "#BOT#URLUpdate"
        $a2 = "Command successfully executed!"
        $a3 = "MUTEXNAME" wide
        $a4 = "NETDATA" wide
        // Versions 3x & 4x & 5x
        $b1 = "FastMM Borland Edition"
        $b2 = "%s, ClassID: %s"
        $b3 = "I wasn't able to open the hosts file"
        $b4 = "#BOT#VisitUrl"
        $b5 = "#KCMDDC"

    condition:
        all of ($a*) or all of ($b*)
}

rule DarkRAT
{
    meta:
        author = " Kevin Breen <kevin@techanarchy.net>"
        date = "2014/04"
        ref = "http://malwareconfig.com/stats/DarkRAT"
        maltype = "Remote Access Trojan"
        family = "darkrat"
        tags = "rat, darkrat"

    strings:
        $a = "@1906dark1996coder@"
        $b = "SHEmptyRecycleBinA"
        $c = "mciSendStringA"
        $d = "add_Shutdown"
        $e = "get_SaveMySettingsOnExit"
        $f = "get_SpecialDirectories"
        $g = "Client.My"

    condition:
        all of them
}

rule Greame
{
    meta:
        author = " Kevin Breen <kevin@techanarchy.net>"
        date = "2014/04"
        ref = "http://malwareconfig.com/stats/Greame"
        maltype = "Remote Access Trojan"
        family = "greame"
        tags = "rat, greame"

    strings:
            $a = {23 23 23 23 40 23 23 23 23 E8 EE E9 F9 23 23 23 23 40 23 23 23 23}
            $b = {23 23 23 23 40 23 23 23 23 FA FD F0 EF F9 23 23 23 23 40 23 23 23 23}
            $c = "EditSvr"
            $d = "TLoader"
            $e = "Stroks"
            $f = "Avenger by NhT"
            $g = "####@####"
            $h = "GREAME"

    condition:
            all of them
}

rule HawkEye
{
    meta:
        author = " Kevin Breen <kevin@techanarchy.net>"
        date = "2015/06"
        ref = "http://malwareconfig.com/stats/HawkEye"
        maltype = "KeyLogger"
        filetype = "exe"
        family = "hawkeye"
        tags = "rat, hawkeye"

    strings:
        $key = "HawkEyeKeylogger" wide
        $salt = "099u787978786" wide
        $string1 = "HawkEye_Keylogger" wide
        $string2 = "holdermail.txt" wide
        $string3 = "wallet.dat" wide
        $string4 = "Keylog Records" wide
    $string5 = "<!-- do not script -->" wide
    $string6 = "\\pidloc.txt" wide
    $string7 = "BSPLIT" wide

    condition:
        $key and $salt and all of ($string*)
}

rule Imminent
{
    meta:
        author = " Kevin Breen <kevin@techanarchy.net>"
        date = "2014/04"
        ref = "http://malwareconfig.com/stats/Imminent"
        maltype = "Remote Access Trojan"
        filetype = "exe"
        family = "imminent"
        tags = "rat, imminent"

    strings:
        $v1a = "DecodeProductKey"
        $v1b = "StartHTTPFlood"
        $v1c = "CodeKey"
        $v1d = "MESSAGEBOX"
        $v1e = "GetFilezillaPasswords"
        $v1f = "DataIn"
        $v1g = "UDPzSockets"
        $v1h = {52 00 54 00 5F 00 52 00 43 00 44 00 41 00 54 00 41}

        $v2a = "<URL>k__BackingField"
        $v2b = "<RunHidden>k__BackingField"
        $v2c = "DownloadAndExecute"
        $v2d = "-CHECK & PING -n 2 127.0.0.1 & EXIT" wide
        $v2e = "england.png" wide
        $v2f = "Showed Messagebox" wide
    condition:
        all of ($v1*) or all of ($v2*)
}

rule Infinity
{
    meta:
        author = " Kevin Breen <kevin@techanarchy.net>"
        date = "2014/04"
        ref = "http://malwareconfig.com/stats/Infinity"
        maltype = "Remote Access Trojan"
        filetype = "exe"
        family = "infinity"
        tags = "rat, infinity"

    strings:
        $a = "CRYPTPROTECT_PROMPTSTRUCT"
        $b = "discomouse"
        $c = "GetDeepInfo"
        $d = "AES_Encrypt"
        $e = "StartUDPFlood"
        $f = "BATScripting" wide
        $g = "FBqINhRdpgnqATxJ.html" wide
        $i = "magic_key" wide

    condition:
        all of them
}

rule jRat
{
    meta:
        author = " Kevin Breen <kevin@techanarchy.net>"
        date = "2014/04"
        ref = "http://malwareconfig.com/stats/jRat"
        maltype = "Remote Access Trojan"
        filetype = "Java"
        family = "jrat"
        tags = "rat, jrat"

    strings:
        $meta = "META-INF"
        $key = "key.dat"
        $conf = "config.dat"
         $jra1 = "enc.dat"
        $jra2 = "a.class"
        $jra3 = "b.class"
        $jra4 = "c.class"
        $reClass1 = /[a-z]\.class/
        $reClass2 = /[a-z][a-f]\.class/

    condition:
       ($meta and $key and $conf and #reClass1 > 10 and #reClass2 > 10) or ($meta and $key and all of ($jra*))
}

rule LostDoor
{
    meta:
        author = " Kevin Breen <kevin@techanarchy.net>"
        date = "2014/04"
        ref = "http://malwareconfig.com/stats/LostDoor"
        maltype = "Remote Access Trojan"
        filetype = "exe"
        family = "lostdoor"
        tags = "rat, lostdoor"

    strings:
        $a0 = {0D 0A 2A 45 44 49 54 5F 53 45 52 56 45 52 2A 0D 0A}
        $a1 = "*mlt* = %"
        $a2 = "*ip* = %"
        $a3 = "*victimo* = %"
        $a4 = "*name* = %"
        $b5 = "[START]"
        $b6 = "[DATA]"
        $b7 = "We Control Your Digital World" wide ascii
        $b8 = "RC4Initialize" wide ascii
        $b9 = "RC4Decrypt" wide ascii

    condition:
        all of ($a*) or all of ($b*)
}

rule LuminosityLink
{
    meta:
        author = " Kevin Breen <kevin@techanarchy.net>"
        date = "2015/06"
        ref = "http://malwareconfig.com/stats/LuminosityLink"
        maltype = "Remote Access Trojan"
        filetype = "exe"
        family = "luminositylink"
        tags = "rat, luminositylink"

    strings:
        $a = "SMARTLOGS" wide
        $b = "RUNPE" wide
        $c = "b.Resources" wide
        $d = "CLIENTINFO*" wide
        $e = "Invalid Webcam Driver Download URL, or Failed to Download File!" wide
        $f = "Proactive Anti-Malware has been manually activated!" wide
        $g = "REMOVEGUARD" wide
        $h = "C0n1f8" wide
        $i = "Luminosity" wide
        $j = "LuminosityCryptoMiner" wide
        $k = "MANAGER*CLIENTDETAILS*" wide

    condition:
        all of them
}

rule LuxNet
{
    meta:
        author = " Kevin Breen <kevin@techanarchy.net>"
        date = "2014/04"
        ref = "http://malwareconfig.com/stats/LuxNet"
        maltype = "Remote Access Trojan"
        filetype = "exe"
        family = "luxnet"
        tags = "rat, luxnet"

    strings:
        $a = "GetHashCode"
        $b = "Activator"
        $c = "WebClient"
        $d = "op_Equality"
        $e = "dickcursor.cur" wide
        $f = "{0}|{1}|{2}" wide

    condition:
        all of them
}

rule NanoCore
{
    meta:
        author = " Kevin Breen <kevin@techanarchy.net>"
        date = "2014/04"
        ref = "http://malwareconfig.com/stats/NanoCore"
        maltype = "Remote Access Trojan"
        filetype = "exe"
        family = "nanocore"
        tags = "rat, nanocore"

    strings:
        $a = "NanoCore"
        $b = "ClientPlugin"
        $c = "ProjectData"
        $d = "DESCrypto"
        $e = "KeepAlive"
        $f = "IPNETROW"
        $g = "LogClientMessage"
        $key = {43 6f 24 cb 95 30 38 39}


    condition:
        6 of them
}

rule NetWire
{
    meta:
        author = " Kevin Breen <kevin@techanarchy.net>"
        date = "2014/04"
        ref = "http://malwareconfig.com/stats/NetWire"
        maltype = "Remote Access Trojan"
        filetype = "exe"
        family = "netwire"
        tags = "rat, netwire"
        
    strings:
        $string1 = "[Scroll Lock]"
        $string2 = "[Shift Lock]"
        $string3 = "200 OK"
        $string4 = "%s.Identifier"
        $string5 = "sqlite3_column_text"
        $string6 = "[%s] - [%.2d/%.2d/%d %.2d:%.2d:%.2d]"
    condition:
        all of them
}

rule njRat
{
    meta:
        author = " Kevin Breen <kevin@techanarchy.net>"
        date = "2014/04"
        ref = "http://malwareconfig.com/stats/njRat"
        maltype = "Remote Access Trojan"
        filetype = "exe"
        family = "njrat"
        tags = "rat, njrat"

    strings:

        $s1 = {7C 00 27 00 7C 00 27 00 7C} // |'|'|
        $s2 = "netsh firewall add allowedprogram" wide
        $s3 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide
        $s4 = "yyyy-MM-dd" wide

        $v1 = "cmd.exe /k ping 0 & del" wide
        $v2 = "cmd.exe /c ping 127.0.0.1 & del" wide
        $v3 = "cmd.exe /c ping 0 -n 2 & del" wide


    condition:
        all of ($s*) and any of ($v*)
}

rule Pandora
{
    meta:
        author = " Kevin Breen <kevin@techanarchy.net>"
        date = "2014/04"
        ref = "http://malwareconfig.com/stats/Pandora"
        maltype = "Remote Access Trojan"
        filetype = "exe"
        family = "pandora"
        tags = "rat, pandora"

    strings:
        $a = "Can't get the Windows version"
        $b = "=M=Q=U=Y=]=a=e=i=m=q=u=y=}="
        $c = "JPEG error #%d" wide
        $d = "Cannot assign a %s to a %s" wide
        $g = "%s, ProgID:"
        $h = "clave"
        $i = "Shell_TrayWnd"
        $j = "melt.bat"
        $k = "\\StubPath"
        $l = "\\logs.dat"
        $m = "1027|Operation has been canceled!"
        $n = "466|You need to plug-in! Double click to install... |"
        $0 = "33|[Keylogger Not Activated!]"

    condition:
        all of them
}

rule Paradox
{
    meta:
        author = " Kevin Breen <kevin@techanarchy.net>"
        date = "2014/04"
        ref = "http://malwareconfig.com/stats/Paradox"
        maltype = "Remote Access Trojan"
        filetype = "exe"
        family = "paradox"
        tags = "rat, paradox"

    strings:
        $a = "ParadoxRAT"
        $b = "Form1"
        $c = "StartRMCam"
        $d = "Flooders"
        $e = "SlowLaris"
        $f = "SHITEMID"
        $g = "set_Remote_Chat"

    condition:
        all of them
}

rule PoisonIvy
{
    meta:
        author = "Kevin Breen <kevin@techanarchy.net>"
        date = "2014/04"
        ref = "http://malwareconfig.com/stats/PoisonIvy"
        family = "poisonivy"
        tags = "rat, poisonivy"

    strings:
        $stub = {04 08 00 53 74 75 62 50 61 74 68 18 04}
        $string1 = "CONNECT %s:%i HTTP/1.0"
        $string2 = "ws2_32"
        $string3 = "cks=u"
        $string4 = "thj@h"
        $string5 = "advpack"
    condition:
        $stub at 0x1620 and all of ($string*) or (all of them)
}

rule PredatorPain
{

    meta:
        author = " Kevin Breen <kevin@techanarchy.net>"
        date = "2014/04"
        ref = "http://malwareconfig.com/stats/PredatorPain"
        maltype = "Remote Access Trojan"
        filetype = "exe"
        family = "predatorpain"
        tags = "rat, predatorpain"

    strings:
        $string1 = "holderwb.txt" wide
        $string3 = "There is a file attached to this email" wide
        $string4 = "screens\\screenshot" wide
        $string5 = "Disablelogger" wide
        $string6 = "\\pidloc.txt" wide
        $string7 = "clearie" wide
        $string8 = "clearff" wide
        $string9 = "emails should be sent to you shortly" wide
        $string10 = "jagex_cache\\regPin" wide
        $string11 = "open=Sys.exe" wide
        $ver1 = "PredatorLogger" wide
        $ver2 = "EncryptedCredentials" wide
        $ver3 = "Predator Pain" wide

    condition:
        7 of ($string*) and any of ($ver*)
}

rule Punisher
{
    meta:
        author = " Kevin Breen <kevin@techanarchy.net>"
        date = "2014/04"
        ref = "http://malwareconfig.com/stats/Punisher"
        maltype = "Remote Access Trojan"
        filetype = "exe"
        family = "punisher"
        tags = "rat, punisher"

    strings:
        $a = "abccba"
        $b = {5C 00 68 00 66 00 68 00 2E 00 76 00 62 00 73}
        $c = {5C 00 73 00 63 00 2E 00 76 00 62 00 73}
        $d = "SpyTheSpy" wide ascii
        $e = "wireshark" wide
        $f = "apateDNS" wide
        $g = "abccbaDanabccb"

    condition:
        all of them
}

rule PythoRAT
{
    meta:
        author = " Kevin Breen <kevin@techanarchy.net>"
        date = "2014/04"
        ref = "http://malwareconfig.com/stats/PythoRAT"
        maltype = "Remote Access Trojan"
        filetype = "exe"
        family = "pythorat"
        tags = "rat, pythorat"

    strings:
        $a = "TKeylogger"
        $b = "uFileTransfer"
        $c = "TTDownload"
        $d = "SETTINGS"
        $e = "Unknown" wide
        $f = "#@#@#"
        $g = "PluginData"
        $i = "OnPluginMessage"

    condition:
        all of them
}

rule SmallNet
{
    meta:
        author = " Kevin Breen <kevin@techanarchy.net>"
        date = "2014/04"
        ref = "http://malwareconfig.com/stats/SmallNet"
        maltype = "Remote Access Trojan"
        filetype = "exe"
        family = "smallnet"
        tags = "rat, smallnet"

    strings:
        $split1 = "!!<3SAFIA<3!!"
        $split2 = "!!ElMattadorDz!!"
        $a1 = "stub_2.Properties"
        $a2 = "stub.exe" wide
        $a3 = "get_CurrentDomain"

    condition:
        ($split1 or $split2) and (all of ($a*))
}

rule SpyGate
{
    meta:
        author = " Kevin Breen <kevin@techanarchy.net>"
        date = "2014/04"
        ref = "http://malwareconfig.com/stats/SpyGate"
        maltype = "Remote Access Trojan"
        filetype = "exe"
        family = "spygate"
        tags = "rat, spygate"

    strings:
        $split = "abccba"
        $a1 = "abccbaSpyGateRATabccba" //$a = Version 0.2.6
        $a2 = "StubX.pdb"
        $a3 = "abccbaDanabccb"
        $b1 = "monikerString" nocase //$b = Version 2.0
        $b2 = "virustotal1"
        $b3 = "get_CurrentDomain"
        $c1 = "shutdowncomputer" wide //$c = Version 2.9
        $c2 = "shutdown -r -t 00" wide
        $c3 = "set cdaudio door closed" wide
        $c4 = "FileManagerSplit" wide
        $c5 = "Chating With >> [~Hacker~]" wide

    condition:
        (all of ($a*) and #split > 40) or (all of ($b*) and #split > 10) or (all of ($c*))
}

rule Sub7Nation
{
    meta:
        author = " Kevin Breen <kevin@techanarchy.net>"
        date = "2014/04"
        ref = "http://malwareconfig.com/stats/Sub7Nation"
        maltype = "Remote Access Trojan"
        filetype = "exe"
        family = "sub7nation"
        tags = "rat, sub7nation"

    strings:
        $a = "EnableLUA /t REG_DWORD /d 0 /f"
        $b = "*A01*"
        $c = "*A02*"
        $d = "*A03*"
        $e = "*A04*"
        $f = "*A05*"
        $g = "*A06*"
        $h = "#@#@#"
        $i = "HostSettings"
        $verSpecific1 = "sevane.tmp"
        $verSpecific2 = "cmd_.bat"
        $verSpecific3 = "a2b7c3d7e4"
        $verSpecific4 = "cmd.dll"

    condition:
        all of them
}

rule unrecom
{
    meta:
        author = " Kevin Breen <kevin@techanarchy.net>"
        date = "2014/04"
        ref = "http://malwareconfig.com/stats/AAR"
        maltype = "Remote Access Trojan"
        filetype = "exe"
        family = "unrecom"
        tags = "rat, unrecom"

    strings:
        $meta = "META-INF"
        $conf = "load/ID"
        $a = "load/JarMain.class"
        $b = "load/MANIFEST.MF"
        $c = "plugins/UnrecomServer.class"

    condition:
        all of them
}

rule Vertex
{

    meta:
        author = " Kevin Breen <kevin@techanarchy.net>"
        date = "2014/04"
        ref = "http://malwareconfig.com/stats/Vertex"
        maltype = "Remote Access Trojan"
        filetype = "exe"
        family = "vertex"
        tags = "rat, vertex"

    strings:
        $string1 = "DEFPATH"
        $string2 = "HKNAME"
        $string3 = "HPORT"
        $string4 = "INSTALL"
        $string5 = "IPATH"
        $string6 = "MUTEX"
        $res1 = "PANELPATH"
        $res2 = "ROOTURL"

    condition:
        all of them
}

rule VirusRat
{
    meta:
        author = " Kevin Breen <kevin@techanarchy.net>"
        date = "2014/04"
        ref = "http://malwareconfig.com/stats/VirusRat"
        maltype = "Remote Access Trojan"
        filetype = "exe"
        family = "virusrat"
        tags = "rat, virusrat"

    strings:
        $string0 = "virustotal"
        $string1 = "virusscan"
        $string2 = "abccba"
        $string3 = "pronoip"
        $string4 = "streamWebcam"
        $string5 = "DOMAIN_PASSWORD"
        $string6 = "Stub.Form1.resources"
        $string7 = "ftp://{0}@{1}" wide
        $string8 = "SELECT * FROM moz_logins" wide
        $string9 = "SELECT * FROM moz_disabledHosts" wide
        $string10 = "DynDNS\\Updater\\config.dyndns" wide
        $string11 = "|BawaneH|" wide

    condition:
        all of them
}

rule xRAT
{
    meta:
        author = " Kevin Breen <kevin@techanarchy.net>"
        date = "2014/04"
        ref = "http://malwareconfig.com/stats/xRat"
        maltype = "Remote Access Trojan"
        filetype = "exe"
        family = "xrat"
        tags = "rat, xrat"

    strings:
        $v1a = "DecodeProductKey"
        $v1b = "StartHTTPFlood"
        $v1c = "CodeKey"
        $v1d = "MESSAGEBOX"
        $v1e = "GetFilezillaPasswords"
        $v1f = "DataIn"
        $v1g = "UDPzSockets"
        $v1h = {52 00 54 00 5F 00 52 00 43 00 44 00 41 00 54 00 41}

        $v2a = "<URL>k__BackingField"
        $v2b = "<RunHidden>k__BackingField"
        $v2c = "DownloadAndExecute"
        $v2d = "-CHECK & PING -n 2 127.0.0.1 & EXIT" wide
        $v2e = "england.png" wide
        $v2f = "Showed Messagebox" wide
    condition:
        all of ($v1*) or all of ($v2*)
}

rule XtremeRAT
{
    meta:
        author = " Kevin Breen <kevin@techanarchy.net>"
        date = "2014/04"
        ref = "http://malwareconfig.com/stats/Xtreme"
        family = "xtreme"
        tags = "rat, xtreme"

    strings:
        $a = "XTREME" wide
        $b = "ServerStarted" wide
        $c = "XtremeKeylogger" wide
        $d = "x.html" wide
        $e = "Xtreme RAT" wide

    condition:
        all of them
}

rule winnti
{
    meta:
        autor = "S2R2"
        family = "winnti"

    strings:
        $tcp = { 60 62 63 64 }
        $http = { 62 62 63 64 }
        $https = { 63 62 63 64 }

    condition:
        $tcp at (filesize + 196 - uint32(filesize - 4)) or $http at (filesize + 196 - uint32(filesize - 4)) or $https at (filesize + 196 - uint32(filesize - 4))
}

