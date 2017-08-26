rule NetWire
{
	meta:
		author = " Kevin Breen <kevin@techanarchy.net>"
		date = "2014/04"
		ref = "http://malwareconfig.com/stats/NetWire"
		maltype = "Remote Access Trojan"
		filetype = "exe"
		
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
