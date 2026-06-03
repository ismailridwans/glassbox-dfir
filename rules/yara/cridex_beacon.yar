/*
 * GLASSBOX bundled YARA rules — minimal set for demo/accuracy benchmarking.
 * NOT for production use without validation.
 * Sources: open-source rule community + custom rules for known samples.
 */

rule Cridex_C2_URL_Pattern {
    meta:
        description = "Detects Cridex C2 URL pattern /zb/v_01_a/ in memory/files"
        author = "GLASSBOX"
        reference = "cridex.vmem analysis (Volatility Foundation)"
        technique = "T1071.001"
    strings:
        $c2_url = "/zb/v_01_a/" ascii nocase
        $c2_url2 = "/zb/v_01_a/in/" ascii nocase
    condition:
        any of them
}

rule Cridex_Reader_SL_Masquerade {
    meta:
        description = "Detects reader_sl.exe masquerading as Adobe Reader SpeedLauncher"
        author = "GLASSBOX"
        technique = "T1036.005"
    strings:
        $name = "reader_sl.exe" ascii nocase
        $path = "AppData\\Local\\Temp\\reader_sl" ascii nocase wide
    condition:
        any of them
}

rule Generic_PE_In_RWX_Region {
    meta:
        description = "MZ header in a RWX memory region — injected PE candidate"
        author = "GLASSBOX"
        technique = "T1055"
    strings:
        $mz = { 4D 5A }
    condition:
        $mz at 0
}

rule Powershell_Encoded_Command {
    meta:
        description = "PowerShell encoded command execution (-enc / -encodedcommand)"
        author = "GLASSBOX"
        technique = "T1059.001"
    strings:
        $enc1 = " -enc " ascii nocase
        $enc2 = " -encodedcommand " ascii nocase
        $enc3 = "FromBase64String" ascii nocase
    condition:
        any of them
}

rule LSASS_Credential_Dump {
    meta:
        description = "Strings associated with LSASS credential dumping"
        author = "GLASSBOX"
        technique = "T1003.001"
    strings:
        $mimikatz = "sekurlsa::logonpasswords" ascii nocase
        $lsass_dump = "lsass.dmp" ascii nocase
        $procdump = "procdump" ascii nocase
    condition:
        any of them
}
