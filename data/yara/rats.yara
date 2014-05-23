rule PoisonIvy
{
    meta:
        author = "Kevin Breen <kevin@techanarchy.net>"
        date = "2014/04"
        ref = "http://malwareconfig.com/stats/PoisonIvy"
        family = "poisonivy"

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
         
rule XtremeRAT
{
    meta:
        author = " Kevin Breen <kevin@techanarchy.net>"
        date = "2014/04"
        ref = "http://malwareconfig.com/stats/Xtreme"
        family = "xtreme"

    strings:
        $a = "XTREME" wide
        $b = "ServerStarted" wide
        $c = "XtremeKeylogger" wide
        $d = "x.html" wide
        $e = "Xtreme RAT" wide

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

    strings:
        $a = "getVer" nocase
        $b = "StartVNC" nocase
        $c = "SendCamList" nocase
        $d = "untPlugin" nocase
        $e = "gethostbyname" nocase
    
    condition:
        all of them
}
          
rule Arcom
{
    meta:
        author = " Kevin Breen <kevin@techanarchy.net>"
        date = "2014/04"
        ref = "http://malwareconfig.com/stats/Arcom"
        family = "arcom"
        
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
           
rule DarkComet
{
    meta:
        author = " Kevin Breen <kevin@techanarchy.net>"
        date = "2014/04"
        ref = "http://malwareconfig.com/stats/DarkComet"
        family = "darkcomet"

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

rule CyberGate
{

    meta:
        author = " Kevin Breen <kevin@techanarchy.net>"
        date = "2014/04"
        ref = "http://malwareconfig.com/stats/CyberGate"
        maltype = "Remote Access Trojan"
        filetype = "exe"
        family = "CyberGate"

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

rule BlueBanana
{
    meta:
        author = " Kevin Breen <kevin@techanarchy.net>"
        date = "2014/04"
        ref = "http://malwareconfig.com/stats/BlueBanana"
        maltype = "Remote Access Trojan"
        filetype = "Java"
        family = "bluebanana"

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

    strings:
        $string1 = "bss_server"
        $string2 = "txtChat"
        $string3 = "UDPFlood"
    condition:
        all of them
}
