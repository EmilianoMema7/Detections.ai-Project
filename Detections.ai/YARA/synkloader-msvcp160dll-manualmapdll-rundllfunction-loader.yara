rule SynkLoader_msvcp160_ManualMapDLL {
    meta:
        author = "detections.ai"
        description = "Detects SynkLoader fake msvcp160.dll module exporting RunDllFunction/ManualMapDLL used to manually map additional DLLs into memory without touching disk, and the Python script that loads it"
        hash = "61F961CFEBDF9967844526649B4B75BBA5B1B83210B70AA1BFFE3F64E6AC3112"
    strings:
        $dll_name = "msvcp160.dll" ascii wide nocase
        $export_rundllfunction = "RunDllFunction" ascii wide
        $func_manualmap = "ManualMapDLL" ascii
        $func_manualresolve = "ManualResolveExport" ascii
        $py_ctypes = "ctypes.WinDLL" ascii
        $py_dllbase64 = "DLL_BASE64" ascii
        $py_b64decode = "base64.b64decode" ascii
        $py_open_export = "b\"open\"" ascii
        $py_nm_export = "b\"nm\"" ascii
    condition:
        $dll_name and
        (
            $export_rundllfunction or $func_manualmap or $func_manualresolve
            or
            (2 of ($py_ctypes, $py_dllbase64, $py_b64decode) and ($py_open_export or $py_nm_export))
        )
}
