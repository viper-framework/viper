/*

Created by 
    The Citizen Lab, Munk School of Global Affairs, University of Toronto
    http://citizenlab.org

As part of the research project
    Comparative Analysis of Targeted Threats Against Human Rights Organizations

Rules initially released (and hopefully updated) here
    https://github.com/citizenlab/malware-signatures

*/


rule APT3102 
{
    meta:
        description = "3102"
        author = "Seth Hardy <seth.hardy@utoronto.ca>"
        last_modified = "2014-06-25"
        
    strings:
        $setupthread = { B9 02 07 00 00 BE ?? ?? ?? ?? 8B F8 6A 00 F3 A5 }
        $ = "rundll32_exec.dll\x00Update"
        // this is in the encrypted code - shares with 9002 variant
        //$ = "POST http://%ls:%d/%x HTTP/1.1"
        
    condition:
       any of them
}

rule APT9002 
{
    meta:
        description = "9002"
        author = "Seth Hardy <seth.hardy@utoronto.ca>"
        last_modified = "2014-06-25"
        
    strings:
        // start code block
        $ = { B9 7A 21 00 00 BE ?? ?? ?? ?? 8B F8 ?? ?? ?? F3 A5 }
        // decryption from other variant with multiple start threads
        $ = { 8A 14 3E 8A 1C 01 32 DA 88 1C 01 8B 54 3E 04 40 3B C2 72 EC }
        $ = "POST http://%ls:%d/%x HTTP/1.1"
        $ = "%%TEMP%%\\%s_p.ax" wide ascii
        $ = "%TEMP%\\uid.ax" wide ascii
        $ = "%%TEMP%%\\%s.ax" wide ascii
        // also triggers on surtr $ = "mydll.dll\x00DoWork"
        $ = "sysinfo\x00sysbin01"
        $ = "\\FlashUpdate.exe"
        
    condition:
       any of them
}

rule Bangat 
{
    meta:
        description = "Bangat"
        author = "Seth Hardy <seth.hardy@utoronto.ca>"
        last_modified = "2014-07-10"
    
    strings:
        // dec [ebp + procname], push eax, push edx, call get procaddress
        $code = { FE 4D ?? 8D 4? ?? 50 5? FF }
        $lib1 = "DreatePipe"
        $lib2 = "HetSystemDirectoryA"
        $lib3 = "SeleaseMutex"
        $lib4 = "DloseWindowStation"
        $lib5 = "DontrolService"
        $file = "~hhC2F~.tmp"
        $mc = "~_MC_3~"

    condition:
       all of ($lib*) or $file or $mc or $code
}

rule Boouset 
{
    meta:
        description = "Boouset"
        author = "Seth Hardy <seth.hardy@utoronto.ca>"
        last_modified = "2014-06-19"
        
    strings:
        $boousetdat = { C6 ?? ?? ?? ?? 00 62 C6 ?? ?? ?? ?? 00 6F C6 ?? ?? ?? ?? 00 6F C6 ?? ?? ?? ?? 00 75 }
        $ = "Q\x00\x00\x00\x00W\x00\x00\x00\x00E\x00\x00\x00\x00R\x00\x00\x00\x00T\x00\x00\x00\x00Y\x00\x00\x00\x00"
        $ = "A\x00\x00\x00\x00S\x00\x00\x00\x00D\x00\x00\x00\x00F\x00\x00\x00\x00G\x00\x00\x00\x00H"
        $ = "Z\x00\x00\x00\x00X\x00\x00\x00\x00C\x00\x00\x00\x00V\x00\x00\x00\x00B\x00\x00\x00\x00N\x00\x00\x00\x00"
        $ = "\\~Z8314.tmp"
        $ = "hulee midimap" wide ascii
        
    condition:
       any of them
}

rule Comfoo 
{
    meta:
        description = "Comfoo"
        author = "Seth Hardy <seth.hardy@utoronto.ca>"
        last_modified = "2014-06-20"
        
    strings:
        $resource = { 6A 6C 6A 59 55 E8 01 FA FF FF }
        $ = "fefj90"
        $ = "iamwaitingforu653890"
        $ = "watchevent29021803"
        $ = "THIS324NEWGAME"
        $ = "ms0ert.temp"
        $ = "\\mstemp.temp"
        
    condition:
       any of them
}

rule Cookies
{
    meta:
        description = "Cookies"
        author = "Seth Hardy <seth.hardy@utoronto.ca>"
        last_modified = "2014-06-20"
        
    strings:
        $zip1 = "ntdll.exePK"
        $zip2 = "AcroRd32.exePK"
        $zip3 = "Setup=ntdll.exe\x0d\x0aSilent=1\x0d\x0a"
        $zip4 = "Setup=%temp%\\AcroRd32.exe\x0d\x0a"
        $exe1 = "Leave GetCommand!"
        $exe2 = "perform exe success!"
        $exe3 = "perform exe failure!"
        $exe4 = "Entry SendCommandReq!"
        $exe5 = "Reqfile not exist!"
        $exe6 = "LeaveDealUpfile!"
        $exe7 = "Entry PostData!"
        $exe8 = "Leave PostFile!"
        $exe9 = "Entry PostFile!"
        $exe10 = "\\unknow.zip" wide ascii
        $exe11 = "the url no respon!"
        
    condition:
      (2 of ($zip*)) or (2 of ($exe*))
}

rule cxpid 
{
    meta:
        description = "cxpid"
        author = "Seth Hardy <seth.hardy@utoronto.ca>"
        last_modified = "2014-06-23"
    
    strings:
        $entryjunk = { 55 8B EC B9 38 04 00 00 6A 00 6A 00 49 75 F9 }
        $ = "/cxpid/submit.php?SessionID="
        $ = "/cxgid/"
        $ = "E21BC52BEA2FEF26D005CF"
        $ = "E21BC52BEA39E435C40CD8"
        $ = "                   -,L-,O+,Q-,R-,Y-,S-"
        
    condition:
       any of them
}

rule Enfal 
{
    meta:
        description = "Enfal"
        author = "Seth Hardy <seth.hardy@utoronto.ca>"
        last_modified = "2014-06-19"
        
    strings:
        // mov al, 20h; sub al, bl; add [ebx+esi], al; push esi; inc ebx; call edi; cmp ebx, eax
        $decrypt = { B0 20 2A C3 00 04 33 56 43 FF D7 3B D8 }
        $ = "D:\\work\\\xe6\xba\x90\xe5\x93\xa5\xe5\x85\x8d\xe6\x9d\x80\\tmp\\Release\\ServiceDll.pdb"
        $ = "e:\\programs\\LuridDownLoader"
        $ = "LuridDownloader for Falcon"
        $ = "DllServiceTrojan"
        $ = "\\k\\\xe6\xa1\x8c\xe8\x9d\xa2\\"
        $ = "EtenFalcon\xef\xbc\x88\xe4\xbf\xae\xe6\x94\xb9\xef\xbc\x89"
        $ = "Madonna\x00Jesus"
        $ = "/iupw82/netstate"
        $ = "fuckNodAgain"
        $ = "iloudermao"
        $ = "Crpq2.cgi"
        $ = "Clnpp5.cgi"
        $ = "Dqpq3ll.cgi"
        $ = "dieosn83.cgi"
        $ = "Rwpq1.cgi"
        $ = "/Ccmwhite"
        $ = "/Cmwhite"
        $ = "/Crpwhite"
        $ = "/Dfwhite"
        $ = "/Query.txt"
        $ = "/Ufwhite"
        $ = "/cgl-bin/Clnpp5.cgi"
        $ = "/cgl-bin/Crpq2.cgi"
        $ = "/cgl-bin/Dwpq3ll.cgi"
        $ = "/cgl-bin/Owpq4.cgi"
        $ = "/cgl-bin/Rwpq1.cgi"
        $ = "/trandocs/mm/"
        $ = "/trandocs/netstat"
        $ = "NFal.exe"
        $ = "LINLINVMAN"
        $ = "7NFP4R9W"
        
    condition:
        any of them
}

rule Ezcob
{
    meta:
        description = "Ezcob"
        author = "Seth Hardy <seth.hardy@utoronto.ca>"
        last_modified = "2014-06-23"
        
    strings:
        $ = "\x12F\x12F\x129\x12E\x12A\x12E\x12B\x12A\x12-\x127\x127\x128\x123\x12"
        $ = "\x121\x12D\x128\x123\x12B\x122\x12E\x128\x12-\x12B\x122\x123\x12D\x12"
        $ = "Ezcob" wide ascii
        $ = "l\x12i\x12u\x122\x120\x121\x123\x120\x124\x121\x126"
        $ = "20110113144935"
        
    condition:
       any of them
}

rule FakeMHTML
{
    meta:
        description = "FAKEM HTML Variant"
        author = "Katie Kleemola <katie.kleemola@utoronto.ca>"
        last_updated = "2014-05-20"
    
    strings:
        // decryption loop
        $s1 = { 8B 55 08 B9 00 50 00 00 8D 3D ?? ?? ?? 00 8B F7 AD 33 C2 AB 83 E9 04 85 C9 75 F5 }
        //mov byte ptr [ebp - x] y, x: 0x10-0x1 y: 0-9,A-F
        $s2 = { C6 45 F? (3?|4?) }

    condition:
        $s1 and #s2 == 16

}

rule Favorite 
{
    meta:
        description = "Favorite"
        author = "Seth Hardy <seth.hardy@utoronto.ca>"
        last_modified = "2014-06-24"
    
    strings:
        // standard string hiding
        $code1 = { C6 45 ?? 3B C6 45 ?? 27 C6 45 ?? 34 C6 45 ?? 75 C6 45 ?? 6B C6 45 ?? 6C C6 45 ?? 3B C6 45 ?? 2F }
        $code2 = { C6 45 ?? 6F C6 45 ?? 73 C6 45 ?? 73 C6 45 ?? 76 C6 45 ?? 63 C6 45 ?? 65 C6 45 ?? 78 C6 45 ?? 65 }
        $string1 = "!QAZ4rfv"
        $file1 = "msupdater.exe"
        $file2 = "FAVORITES.DAT"
        
    condition:
       any of ($code*) or any of ($string*) or all of ($file*)
}

rule Glasses 
{
    meta:
        description = "Glasses"
        author = "Seth Hardy <seth.hardy@utoronto.ca>"
        last_modified = "2014-07-22"
        
    strings:
        $code1 = { B8 AB AA AA AA F7 E1 D1 EA 8D 04 52 2B C8 }
        $code2 = { B8 56 55 55 55 F7 E9 8B 4C 24 1C 8B C2 C1 E8 1F 03 D0 49 3B CA }
        $str1 = "thequickbrownfxjmpsvalzydg"
        $str2 = "Mozilla/4.0 (compatible; Windows NT 5.1; MSIE 7.0; Trident/4.0; %s.%s)"
        $str3 = "\" target=\"NewRef\"></a>"
 
    condition:
        any of ($code*) or all of ($str*)
}

rule iexpl0re 
{
    meta:
        description = "iexpl0re"
        author = "Seth Hardy <seth.hardy@utoronto.ca>"
        last_modified = "2014-07-21"
        
    strings:
        $ = { 47 83 FF 64 0F 8C 6D FF FF FF 33 C0 5F 5E 5B C9 C3 }
        $ = { 80 74 0D A4 44 41 3B C8 7C F6 68 04 01 00 00 }
        $ = { 8A C1 B2 07 F6 EA 30 04 31 41 3B 4D 10 7C F1 }
        $ = { 47 83 FF 64 0F 8C 79 FF FF FF 33 C0 5F 5E 5B C9 C3 }
        // 88h decrypt
        $ = { 68 88 00 00 00 68 90 06 00 00 68 ?? ?? ?? ?? 89 3? E8 }
        $ = { BB 88 00 00 00 53 68 90 06 00 00 68 ?? ?? ?? ?? 89 3? E8 }
        $ = "%USERPROFILE%\\IEXPL0RE.EXE"
        $ = "\"<770j (("
        $ = "\\Users\\%s\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\IEXPL0RE.LNK"
        $ = "\\Documents and Settings\\%s\\Application Data\\Microsoft\\Internet Explorer\\IEXPL0RE.EXE"
        $ = "LoaderV5.dll"
        // stage 2
        $ = "POST /index%0.9d.asp HTTP/1.1"
        $ = "GET /search?n=%0.9d&"
        $ = "DUDE_AM_I_SHARP-3.14159265358979x6.626176"
        $ = "WHO_A_R_E_YOU?2.99792458x1.25663706143592"
        $ = "BASTARD_&&_BITCHES_%0.8x"
        $ = "c:\\bbb\\eee.txt"
        
    condition:
        any of them
}

rule IMuler 
{
    meta:
        description = "IMuler"
        author = "Seth Hardy <seth.hardy@utoronto.ca>"
        last_modified = "2014-06-16"
        
    strings:
        // Load these function strings 4 characters at a time. These check the first two blocks:
        $L4_tmpSpotlight = { C7 ?? 2F 74 6D 70 C7 ?? 04 2F 53 70 6F }
        $L4_TMPAAABBB = { C7 ?? ?? ?? ?? ?? 54 4D 50 41 C7 ?? ?? ?? ?? ?? 41 41 42 42 }
        $L4_FILEAGENTVer = { C7 ?? 46 49 4C 45 C7 ?? 04 41 47 45 4E }
        $L4_TMP0M34JDF8 = { C7 ?? ?? ?? ?? ?? 54 4D 50 30 C7 ?? ?? ?? ?? ?? 4D 33 34 4A }
        $L4_tmpmdworker = { C7 ?? 2F 74 6D 70 C7 ?? 04 2F 2E 6D 64 }
        $str1 = "/cgi-mac/"
        $str2 = "xnocz1"
        $str3 = "checkvir.plist"
        $str4 = "/Users/apple/Documents/mac back"
        $str5 = "iMuler2"
        $str6 = "/Users/imac/Desktop/macback/"
        $str7 = "xntaskz.gz"
        $str8 = "2wmsetstatus.cgi"
        $str9 = "launch-0rp.dat"
        $str10 = "2wmupload.cgi"
        $str11 = "xntmpz"
        $str12 = "2wmrecvdata.cgi"
        $str13 = "xnorz6"
        $str14 = "2wmdelfile.cgi"
        $str15 = "/LanchAgents/checkvir"
        $str16 = "0PERA:%s"
        $str17 = "/tmp/Spotlight"
        $str18 = "/tmp/launch-ICS000"
        
    condition:
        all of ($L4*) or any of ($str*)
}

rule Insta11 
{
    meta:
        description = "Insta11"
        author = "Seth Hardy <seth.hardy@utoronto.ca>"
        last_modified = "2014-06-23"
    
    strings:
        // jmp $+5; push 423h
        $jumpandpush = { E9 00 00 00 00 68 23 04 00 00 }
        $ = "XTALKER7"
        $ = "Insta11 Microsoft" wide ascii
        $ = "wudMessage"
        $ = "ECD4FC4D-521C-11D0-B792-00A0C90312E1"
        $ = "B12AE898-D056-4378-A844-6D393FE37956"
        
    condition:
       any of them
}

rule LuckyCat 
{
    meta:
        description = "LuckyCat"
        author = "Seth Hardy <seth.hardy@utoronto.ca>"
        last_modified = "2014-06-19"
        
    strings:
        $xordecrypt = { BF 0F 00 00 00 F7 F7 ?? ?? ?? ?? 32 14 39 80 F2 7B }
        $dll = { C6 ?? ?? ?? 64 C6 ?? ?? ?? 6C C6 ?? ?? ?? 6C }
        $commonletters = { B? 63 B? 61 B? 73 B? 65 }
        $str1 = { 77 76 75 7B 7A 79 78 7F 7E 7D 7C 73 72 71 70 }
        $str2 = "%s\\~temp.vbs"
        $str3 = "count.php\x00"
        $str4 = /WMILINK=.*TrojanName=/
        $str5 = "d0908076343423d3456.tmp"
        $str6 = "cmd /c dir /s /a C:\\\\ >'+tmpfolder+'\\\\C.tmp"
        $str7 = "objIP.DNSHostName+'_'+objIP.MACAddress.split(':').join('')+'_'+addinf+'@')"
        
    condition:
       $xordecrypt or ($dll and $commonletters) or any of ($str*)
}

rule LURK0
{
    meta:
        description = "LURK0"
        author = "Katie Kleemola <katie.kleemola@utoronto.ca>"
        last_updated = "2014-07-22"

    strings:    
        $header = { C6 [5] 4C C6 [5] 55 C6 [5] 52 C6 [5] 4B C6 [5] 30 }
        // internal names
        $str1 = "Butterfly.dll"
        $str2 = /\\BT[0-9.]+\\ButterFlyDLL\\/
        $str3 = "ETClientDLL"
        // dbx
        $str4 = "\\DbxUpdateET\\" wide
        $str5 = "\\DbxUpdateBT\\" wide
        $str6 = "\\DbxUpdate\\" wide
        // other folders
        $str7 = "\\Micet\\"
        // embedded file names
        $str8 = "IconCacheEt.dat" wide
        $str9 = "IconConfigEt.dat" wide
        $str10 = "ERXXXXXXX" wide
        $str11 = "111" wide
        $str12 = "ETUN" wide

    condition:
        $header and any of ($str*)
}

rule MacControl
{
    meta:
        description = "MacControl"
        author = "Seth Hardy <seth.hardy@utoronto.ca>"
        last_modified = "2014-06-17"
        
    strings:
        // Load these function strings 4 characters at a time. These check the first two blocks:
        $L4_Accept = { C7 ?? 41 63 63 65 C7 ?? 04 70 74 3A 20 }
        $L4_AcceptLang = { C7 ?? 41 63 63 65 C7 ?? 04 70 74 2D 4C }
        $L4_Pragma = { C7 ?? 50 72 61 67 C7 ?? 04 6D 61 3A 20 }
        $L4_Connection = { C7 ?? 43 6F 6E 6E C7 ?? 04 65 63 74 69 }
        $GEThgif = { C7 ?? 47 45 54 20 C7 ?? 04 2F 68 2E 67 }
        $str1 = "HTTPHeadGet"
        $str2 = "/Library/launched"
        $str3 = "My connect error with no ip!"
        $str4 = "Send File is Failed"
        $str5 = "****************************You Have got it!****************************"
        
    condition:
        all of ($L4*) or $GEThgif or any of ($str*)
}

rule Mirage
{
    meta:
        description = "Mirage"
        author = "Seth Hardy <seth.hardy@utoronto.ca>"
        last_modified = "2014-06-25"
        
    strings:
        $ = "Neo,welcome to the desert of real." wide ascii
        $ = "/result?hl=en&id=%s"
        
    condition:
        any of them
}

rule Mongal
{
    meta:
        description = "Mongal"
        author = "Seth Hardy <seth.hardy@utoronto.ca>"
        last_modified = "2014-07-15"
    
    strings:
        // gettickcount value checking
        $ = { 8B C8 B8 D3 4D 62 10 F7 E1 C1 EA 06 2B D6 83 FA 05 76 EB }
        $ = "NSCortr.dll"
        $ = "NSCortr1.dll"
        $ = "Sina.exe"
        
    condition:
        any of them
}

rule Naikon
{
    meta:
        description = "Naikon"
        author = "Seth Hardy <seth.hardy@utoronto.ca>"
        last_modified = "2014-06-25"
    
    strings:
        // decryption
        $decr1 = { 0F AF C1 C1 E0 1F } // imul eax, ecx; shl eah, 1fh
        $decr2 = { 35 5A 01 00 00} // xor eax, 15ah
        $decr3 = { 81 C2 7F 14 06 00 } // add edx, 6147fh
        $str1 = "NOKIAN95/WEB"
        $str2 = "/tag=info&id=15"
        $str3 = "skg(3)=&3.2d_u1"
        $str4 = "\\Temp\\iExplorer.exe"
        $str5 = "\\Temp\\\"TSG\""
        
    condition:
       all of ($decr*) or any of ($str*)
}

rule nAspyUpdate
{
    meta:
        description = "nAspyUpdate"
        author = "Seth Hardy <seth.hardy@utoronto.ca>"
        last_modified = "2014-07-14"
    
    strings:
        // decryption loop in dropper
        $ = { 8A 54 24 14 8A 01 32 C2 02 C2 88 01 41 4E 75 F4 }
        $ = "\\httpclient.txt"
        $ = "password <=14"
        $ = "/%ldn.txt"
        $ = "Kill You\x00"
        
    condition:
        any of them
}

//will match both exe and dll components
rule NetTraveler
{
    meta:
        description = "NetTraveler (includes NetPass variant)"
        author = "Katie Kleemola <katie.kleemola@utoronto.ca>"
        last_updated = "2014-05-20"
    
    strings:
        //dll component exports
        $ = "?InjectDll@@YAHPAUHWND__@@K@Z"
        $ = "?UnmapDll@@YAHXZ"
        $ = "?g_bSubclassed@@3HA"
        //network strings
        $ = "?action=updated&hostid="
        $ = "travlerbackinfo"
        $ = "?action=getcmd&hostid="
        $ = "%s?action=gotcmd&hostid="
        $ = "%s?hostid=%s&hostname=%s&hostip=%s&filename=%s&filestart=%u&filetext="
        //debugging strings
        $ = "\x00Method1 Fail!!!!!\x00"
        $ = "\x00Method3 Fail!!!!!\x00"
        $ = "\x00method currect:\x00"
        $ = /\x00\x00[\w\-]+ is Running!\x00\x00/
        $ = "\x00OtherTwo\x00"
        $exif1 = "Device Protect ApplicatioN" wide
        $exif2 = "beep.sys" wide //embedded exe name
        $exif3 = "BEEP Driver" wide //embedded exe description
        $string1 = "\x00NetPass Update\x00"
        $string2 = "\x00%s:DOWNLOAD\x00"
        $string3 = "\x00%s:UPDATE\x00"
        $string4 = "\x00%s:uNINSTALL\x00"

    condition:
        any of them
}

rule NSFree
{
    meta:
        description = "NSFree"
        author = "Seth Hardy <seth.hardy@utoronto.ca>"
        last_modified = "2014-06-24"
    
    strings:
        // push vars then look for MZ
        $code1 = { 53 56 57 66 81 38 4D 5A }
        // nops then look for PE\0\0
        $code2 = { 90 90 90 90 81 3F 50 45 00 00 }
        $str1 = "\\MicNS\\" nocase
        $str2 = "NSFreeDll" wide ascii
        // xor 0x58 dos stub
        $str3 = { 0c 30 31 2b 78 28 2a 37 3f 2a 39 35 78 3b 39 36 36 37 }
        
    condition:
       all of ($code*) or any of ($str*)
}

rule Olyx
{
    meta:
        description = "Olyx"
        author = "Seth Hardy <seth.hardy@utoronto.ca>"
        last_modified = "2014-06-19"
        
    strings:
        $six = { C7 40 04 36 36 36 36 C7 40 08 36 36 36 36 }
        $slash = { C7 40 04 5C 5C 5C 5C C7 40 08 5C 5C 5C 5C }
        $ = "/Applications/Automator.app/Contents/MacOS/DockLight"
       
    condition:
        any of them
}

rule PlugXBoot
{
    meta:
        description = "PlugX"
        author = "Seth Hardy <seth.hardy@utoronto.ca>"
        last_modified = "2014-06-12"
        
    strings:
        $callpop = { E8 00 00 00 00 58 }
        // Compares [eax+n] to GetProcAdd, one character at a time. This goes up to GetP:
        $GetProcAdd = { 80 38 47 75 36 80 78 01 65 75 30 80 78 02 74 75 2A 80 78 03 50 }
        // Load these function strings 4 characters at a time. These check the first two blocks:
        $L4_LoadLibraryA = { C7 ( ?? ?? | ?? ?? ?? ?? ?? ) 4C 6F 61 64 C7 ( ?? ?? | ?? ?? ?? ?? ?? ) 4C 69 62 72 }
        $L4_VirtualAlloc = { C7 ( ?? ?? | ?? ?? ?? ?? ?? ) 56 69 72 74 C7 ( ?? ?? | ?? ?? ?? ?? ?? ) 75 61 6C 41 }
        $L4_VirtualFree = { C7 ( ?? ?? | ?? ?? ?? ?? ?? ) 56 69 72 74 C7 ( ?? ?? | ?? ?? ?? ?? ?? ) 75 61 6C 46 }
        $L4_ExitThread = { C7 ( ?? ?? | ?? ?? ?? ?? ?? ) 45 78 69 74 C7 ( ?? ?? | ?? ?? ?? ?? ?? ) 54 68 72 65 }
        $L4_ntdll = { C7 ( ?? ?? | ?? ?? ?? ?? ?? ) 6E 74 64 6C 66 C7 ( ?? ?? | ?? ?? ?? ?? ?? ) C6 00 }
        $L4_RtlDecompressBuffer = { C7 ( ?? ?? | ?? ?? ?? ?? ?? ) 52 74 6C 44 C7 ( ?? ?? | ?? ?? ?? ?? ?? ) 65 63 6F 6D }
        $L4_memcpy = { C7 ( ?? ?? | ?? ?? ?? ?? ?? ) 6D 65 6D 63 66 C7 ( ?? ?? | ?? ?? ?? ?? ?? ) 70 79 }
        $BootLDR = "boot.ldr" wide ascii
        $Dwork = "d:\\work" nocase
        $Plug25 = "plug2.5"
        $Plug30 = "Plug3.0"
        $Shell6 = "Shell6"
        
    condition:
        ($callpop at 0) or $GetProcAdd or (all of ($L4_*)) or $BootLDR or ($Dwork and ($Plug25 or $Plug30 or $Shell6))
}

rule PubSab
{
    meta:
        description = "PubSab"
        author = "Seth Hardy <seth.hardy@utoronto.ca>"
        last_modified = "2014-06-19"
        
    strings:
        $decrypt = { 6B 45 E4 37 89 CA 29 C2 89 55 E4 }
        $ = "_deamon_init"
        $ = "com.apple.PubSabAgent"
        $ = "/tmp/screen.jpeg"
       
    condition:
        any of them
}

rule Quarian
{
    meta:
        description = "Quarian"
        author = "Seth Hardy <seth.hardy@utoronto.ca>"
        last_modified = "2014-07-09"
    
    strings:
        // decrypt in intelnat.sys
        $ = { C1 E? 04 8B ?? F? C1 E? 05 33 C? }
        // decrypt in mswsocket.dll
        $ = { C1 EF 05 C1 E3 04 33 FB }
        $ = { 33 D8 81 EE 47 86 C8 61 }
        // loop in msupdate.dll
        $ = { FF 45 E8 81 45 EC CC 00 00 00 E9 95 FE FF FF }
        $ = "s061779s061750"
        $ = "[OnUpLoadFile]"
        $ = "[OnDownLoadFile]"
        $ = "[FileTransfer]"
        $ = "---- Not connect the Manager, so start UnInstall ----"
        $ = "------- Enter CompressDownLoadDir ---------"
        $ = "------- Enter DownLoadDirectory ---------"
        $ = "[HandleAdditionalData]"
        $ = "[mswsocket.dll]"
        $ = "msupdate.dll........Enter ThreadCmd!"
        $ = "ok1-1"
        $ = "msupdate_tmp.dll"
        $ = "replace Rpcss.dll successfully!"
        $ = "f:\\loadhiddendriver-mdl\\objfre_win7_x86\\i386\\intelnat.pdb"
        $ = "\\drivercashe\\" wide ascii
        $ = "\\microsoft\\windwos\\" wide ascii
        $ = "\\DosDevices\\LOADHIDDENDRIVER" wide ascii
        $ = "\\Device\\LOADHIDDENDRIVER" wide ascii
        $ = "Global\\state_maping" wide ascii
        $ = "E:\\Code\\2.0\\2.0_multi-port\\2.0\\ServerInstall_New-2010-0913_sp3\\msupdataDll\\Release\\msupdate_tmp.pdb"
        $ = "Global\\unInstall_event_1554_Ower" wide ascii
        
    condition:
       any of them
}

rule RegSubDat
{
    meta:
        description = "RegSubDat"
        author = "Seth Hardy <seth.hardy@utoronto.ca>"
        last_modified = "2014-07-14"
    
    strings:
        // decryption loop
        $code1 = { 80 34 3? 99 40 (3D FB 65 00 00 | 3B C6) 7? F? }
        // push then pop values
        $code2 = { 68 FF FF 7F 00 5? }
        $code3 = { 68 FF 7F 00 00 5? }
        $avg1 = "Button"
        $avg2 = "Allow"
        $avg3 = "Identity Protection"
        $avg4 = "Allow for all"
        $avg5 = "AVG Firewall Asks For Confirmation"
        $mutex = "0x1A7B4C9F"
        
    condition:
       all of ($code*) or all of ($avg*) or $mutex
}


rule GmRemote
{
    meta:
        description = "GmRemote"
        author = "Katie Kleemola <katie.kleemola@utoronto.ca>"
        last_updated = "07-25-2014"
    
    strings:
        $rshared1 = "nView_DiskLoydb" wide
        $rshared2 = "nView_KeyLoydb" wide
        $rshared3 = "nView_skins" wide
        $rshared4 = "UsbLoydb" wide
        $rshared5 = "%sBurn%s" wide
        $rshared6 = "soul" wide
        $gmremote1 = "\x00x86_GmRemote.dll\x00"
        $gmremote2 = "\x00D:\\Project\\GTProject\\Public\\List\\ListManager.cpp\x00"
        $gmremote3 = "\x00GmShutPoint\x00"
        $gmremote4 = "\x00GmRecvPoint\x00"
        $gmremote5 = "\x00GmInitPoint\x00"
        $gmremote6 = "\x00GmVerPoint\x00"
        $gmremote7 = "\x00GmNumPoint\x00"
        $gmremote8 = "_Gt_Remote_" wide
        $gmremote9 = "%sBurn\\workdll.tmp" wide
    
    condition:
        any of ($rshared*) and any of ($gmremote*)
}

rule Remote
{
    meta:
        description = "Remote"
        author = "Katie Kleemola <katie.kleemola@utoronto.ca>"
        last_updated = "07-25-2014"
    
    strings:
        $rshared1 = "nView_DiskLoydb" wide
        $rshared2 = "nView_KeyLoydb" wide
        $rshared3 = "nView_skins" wide
        $rshared4 = "UsbLoydb" wide
        $rshared5 = "%sBurn%s" wide
        $rshared6 = "soul" wide
        $remote1 = "\x00Remote.dll\x00"
        $remote2 = "\x00CGm_PlugBase::"
        $remote3 = "\x00ServiceMain\x00_K_H_K_UH\x00"
        $remote4 = "\x00_Remote_\x00" wide

    condition:
        any of ($rshared*) and any of ($remote*)
}

rule Rookie
{
    meta:
        description = "Rookie"
        author = "Seth Hardy <seth.hardy@utoronto.ca>"
        last_modified = "2014-06-25"
        
    strings:
        // hidden AutoConfigURL
        $ = { C6 ?? ?? ?? 41 C6 ?? ?? ?? 75 [4] C6 ?? ?? ?? 6F C6 ?? ?? ?? 43 C6 ?? ?? ?? 6F C6 ?? ?? ?? 6E C6 ?? ?? ?? 66 }
        // hidden ProxyEnable
        $ = { C6 ?? ?? ?? 50 [4] C6 ?? ?? ?? 6F C6 ?? ?? ?? 78 C6 ?? ?? ?? 79 C6 ?? ?? ?? 45 C6 ?? ?? ?? 6E C6 ?? ?? ?? 61 }
        // xor on rand value?
        $ = { 8B 1D 10 A1 40 00 [18] FF D3 8A 16 32 D0 88 16 }
        $ = "RookIE/1.0"
        
    condition:
       any of them
}

rule Rooter
{
    meta:
        description = "Rooter"
        author = "Seth Hardy <seth.hardy@utoronto.ca>"
        last_modified = "2014-07-10"
    
    strings:
        // xor 0x30 decryption
        $code = { 80 B0 ?? ?? ?? ?? 30 40 3D 00 50 00 00 7C F1 }
        $group1 = "seed\x00"
        $group2 = "prot\x00"
        $group3 = "ownin\x00"
        $group4 = "feed0\x00"
        $group5 = "nown\x00"

    condition:
       3 of ($group*) or $code
}

rule SafeNet
{
    meta:
        description = "SafeNet"
        author = "Seth Hardy <seth.hardy@utoronto.ca>"
        last_modified = "2014-07-16"
        
    strings:
        // add edi, 14h; cmp edi, 50D0F8h
        $ = { 83 C7 14 81 FF F8 D0 40 00 }
        $ = "6dNfg8Upn5fBzGgj8licQHblQvLnUY19z5zcNKNFdsDhUzuI8otEsBODrzFCqCKr"
        $ = "/safe/record.php"
        $ = "_Rm.bat" wide ascii
        $ = "try\x0d\x0a\x09\x09\x09\x09  del %s" wide ascii
        $ = "Ext.org" wide ascii
        
    condition:
        any of them
}

rule Scarhikn
{
    meta:
        description = "Scarhikn"
        author = "Seth Hardy <seth.hardy@utoronto.ca>"
        last_modified = "2014-06-25"
    
    strings:
        // decryption
        $ = { 8B 06 8A 8B ?? ?? ?? ?? 30 0C 38 03 C7 55 43 E8 ?? ?? ?? ?? 3B D8 59 72 E7 }
        $ = { 8B 02 8A 8D ?? ?? ?? ?? 30 0C 30 03 C6 8B FB 83 C9 FF 33 C0 45 F2 AE F7 D1 49 3B E9 72 E2 }
        $ = "9887___skej3sd"
        $ = "haha123"
        
    condition:
       any of them
}

rule Surtr
{
    meta: 
        author = "Katie Kleemola <katie.kleemola@utoronto.ca>"
        description = "Surtr"
        last_updated = "2014-07-16"
    
    strings:
        //decrypt config
        $ = { 8A ?? ?? 84 ?? ?? 74 ?? 3C 01 74 ?? 34 01 88 41 3B ?? 72 ?? }
        //if Burn folder name is not in strings
        $ = { C6 [3] 42 C6 [3] 75 C6 [3] 72 C6 [3] 6E C6 [3] 5C }
        //mov char in _Fire
        $ = { C6 [3] 5F C6 [3] 46 C6 [3] 69 C6 [3] 72 C6 [3] 65 C6 [3] 2E C6 [3] 64 }
        $ = "\x00soul\x00"
        $ = "\x00InstallDll.dll\x00"
        $ = "\x00_One.dll\x00"
        $ = "_Fra.dll"
        $ = "CrtRunTime.log"
        $ = "Prod.t"
        $ = "Proe.t"
        $ = "Burn\\"
        $ = "LiveUpdata_Mem\\"

    condition:
        any of them
}

rule T5000
{
    meta:
        description = "T5000"
        author = "Seth Hardy <seth.hardy@utoronto.ca>"
        last_modified = "2014-06-26"
        
    strings:
        $ = "_tmpR.vbs"
        $ = "_tmpg.vbs"
        $ = "Dtl.dat" wide ascii
        $ = "3C6FB3CA-69B1-454f-8B2F-BD157762810E"
        $ = "EED5CA6C-9958-4611-B7A7-1238F2E1B17E"
        $ = "8A8FF8AD-D1DE-4cef-B87C-82627677662E"
        $ = "43EE34A9-9063-4d2c-AACD-F5C62B849089"
        $ = "A8859547-C62D-4e8b-A82D-BE1479C684C9"
        $ = "A59CF429-D0DD-4207-88A1-04090680F714"
        $ = "utd_CE31" wide ascii
        $ = "f:\\Project\\T5000\\Src\\Target\\1 KjetDll.pdb"
        $ = "l:\\MyProject\\Vc 7.1\\T5000\\T5000Ver1.28\\Target\\4 CaptureDLL.pdb"
        $ = "f:\\Project\\T5000\\Src\\Target\\4 CaptureDLL.pdb"
        $ = "E:\\VS2010\\xPlat2\\Release\\InstRes32.pdb"
        
    condition:
       any of them
}

rule Vidgrab
{
    meta:
        description = "Vidgrab"
        author = "Seth Hardy <seth.hardy@utoronto.ca>"
        last_modified = "2014-06-20"
        
    strings:
        $divbyzero = { B8 02 00 00 00 48 48 BA 02 00 00 00 83 F2 02 F7 F0 }
        // add eax, ecx; xor byte ptr [eax], ??h; inc ecx
        $xorloop = { 03 C1 80 30 (66 | 58) 41 }
        $junk = { 8B 4? ?? 8B 4? ?? 03 45 08 52 5A }
        $str1 = "IDI_ICON5" wide ascii
        $str2 = "starter.exe"
        $str3 = "wmifw.exe"
        $str4 = "Software\\rar"
        $str5 = "tmp092.tmp"
        $str6 = "temp1.exe"
        
    condition:
       ($divbyzero and $xorloop and $junk) or 3 of ($str*)
}

rule Warp
{
    meta:
        description = "Warp"
        author = "Seth Hardy <seth.hardy@utoronto.ca>"
        last_modified = "2014-07-10"
    
    strings:
        // character replacement
        $ = { 80 38 2B 75 03 C6 00 2D 80 38 2F 75 03 C6 00 5F }
        $ = "/2011/n325423.shtml?"
        $ = "wyle"
        $ = "\\~ISUN32.EXE"

    condition:
       any of them
}

rule Wimmie
{
    meta:
        description = "Wimmie"
        author = "Seth Hardy <seth.hardy@utoronto.ca>"
        last_modified = "2014-07-17"
        
    strings:
        // shellcode - no binary, WMI malware
        $ = { 49 30 24 39 83 F9 00 77 F7 8D 3D 4D 10 40 00 B9 0C 03 00 00 }
        $xordecrypt = {B9 B4 1D 00 00 [8] 49 30 24 39 83 F9 00 }
        $ = "\x00ScriptMan"
        $ = "C:\\WINDOWS\\system32\\sysprep\\cryptbase.dll" wide ascii
        $ = "ProbeScriptFint" wide ascii
        $ = "ProbeScriptKids"
        
    condition:
        any of them
}

rule Xtreme
{
    meta:
        description = "XtremeRAT"
        author = "Seth Hardy <seth.hardy@utoronto.ca>"
        last_modified = "2014-07-09"
    
    strings:
        // call; fstp st
        $code1 = { E8 ?? ?? ?? ?? DD D8 }
        // hiding string
        $code2 = { C6 85 ?? ?? ?? ?? 4D C6 85 ?? ?? ?? ?? 70 C6 85 ?? ?? ?? ?? 64 C6 85 ?? ?? ?? ?? 62 C6 85 ?? ?? ?? ?? 6D }
        $str1 = "dqsaazere"
        $str2 = "-GCCLIBCYGMING-EH-TDM1-SJLJ-GTHR-MINGW32"
        
    condition:
       all of ($code*) or any of ($str*)
}

rule Yayih
{
    meta:
        description = "Yayih"
        author = "Seth Hardy <seth.hardy@utoronto.ca>"
        last_modified = "2014-07-11"
    
    strings:
        //  encryption
        $ = { 80 04 08 7A 03 C1 8B 45 FC 80 34 08 19 03 C1 41 3B 0A 7C E9 }
        $ = "/bbs/info.asp"
        $ = "\\msinfo.exe"
        $ = "%s\\%srcs.pdf"
        $ = "\\aumLib.ini"

    condition:
       any of them
}
