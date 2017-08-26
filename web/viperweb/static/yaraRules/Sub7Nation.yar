rule Sub7Nation
{
	meta:
		author = " Kevin Breen <kevin@techanarchy.net>"
		date = "2014/04"
		ref = "http://malwareconfig.com/stats/Sub7Nation"
		maltype = "Remote Access Trojan"
		filetype = "exe"

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