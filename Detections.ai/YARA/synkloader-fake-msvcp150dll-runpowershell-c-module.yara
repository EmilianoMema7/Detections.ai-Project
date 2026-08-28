rule SynkLoader_Fake_msvcp150_RunPowerShell {
    meta:
        author = "detections.ai"
        description = "Detects the SynkLoader fake msvcp150.dll component that exports RunPowerShell/RunPowerShellW to execute PowerShell entirely in memory"
        hash = "61f961cfebdf9967844526649b4b75bba5b1b83210b70aa1bffe3f64e6ac3112"
    strings:
        $export1 = "RunPowerShell" ascii
        $export2 = "RunPowerShellW" ascii
        $export3 = "InitializePowerShell" ascii
        $export4 = "ExecutePowerShellCommand" ascii
        $export5 = "CleanupPowerShell" ascii
        $export6 = "FreeString" ascii
        $pdb = "pwshnewdll.pdb" ascii
        $assembly_title = "PowerShell Single Function DLL" ascii wide
        $assembly_desc = "Single exported function for PowerShell execution" ascii wide
        $assembly_product = "pwsldll_single" ascii wide
        $_header_mz = { 4D 5A }
    condition:
        $_header_mz at 0 and
        (
            2 of ($export1, $export2, $export3, $export4, $export5, $export6)
            or $pdb
            or any of ($assembly_title, $assembly_desc, $assembly_product)
        )
}
