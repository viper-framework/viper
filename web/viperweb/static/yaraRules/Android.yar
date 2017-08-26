rule Android
{
	meta:
		description = "This is a generic detaction for ANY Android application."
		filetype = "apk"

	strings:
		$Header = "PK"
		$b = "assets"
		$c = "META-INF"
		$d = "AndroidManifest.xml"
		$e = "classes.dex"

	condition:
		all of them
}