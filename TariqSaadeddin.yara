rule TariqSaadeddin
{
meta: 
		description = "Simple Yara Rule for Malwariachi"
strings: 
		$a = "VirtualProtect"
		$b = "Malwariachi"
		$c = "Caruso"
		$d = "Gestapo"
		$e = "Ops, Potato.dll is missing!"
		$x = {4D 5A}

condition: 
		($a or $b or $c or $d or $e and $x)
}
