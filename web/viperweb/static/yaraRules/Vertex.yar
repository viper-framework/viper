rule Vertex
{

	meta:
		author = " Kevin Breen <kevin@techanarchy.net>"
		date = "2014/04"
		ref = "http://malwareconfig.com/stats/Vertex"
		maltype = "Remote Access Trojan"
		filetype = "exe"

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
