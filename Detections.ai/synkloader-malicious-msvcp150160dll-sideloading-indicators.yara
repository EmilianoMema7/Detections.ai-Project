import "pe"

rule SynkLoader_Masquerading_msvcp_DLL {
    meta:
        author = "detections.ai"
        description = "Detects DLLs named msvcp150.dll or msvcp160.dll containing SynkLoader-specific reflective PE mapping and DLL sideloading export markers used to masquerade as legitimate Visual C++ runtime libraries"
    strings:
        $exp1 = "InitializePowerShell" ascii
        $exp2 = "ExecutePowerShellCommand" ascii
        $exp3 = "FreeString" ascii
        $exp4 = "CleanupPowerShell" ascii
        $exp5 = "RunDllFunction" ascii
        $title = "PowerShell Single Function DLL" ascii wide
        $product = "pwsldll_single" ascii wide
        $desc = "Single exported function for PowerShell execution" ascii wide
    condition:
        pe.is_pe and 2 of ($exp*, $title, $product, $desc)
}