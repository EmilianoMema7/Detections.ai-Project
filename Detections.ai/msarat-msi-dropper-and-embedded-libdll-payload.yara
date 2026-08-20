rule msaRAT_MSI_dropper_lib_dll {
  meta:
    author = "detections.ai"
    description = "Detects msaRAT MSI dropper (update_ms.msi) and embedded lib.dll payload via RUN export and msa* binding strings"
  strings:
    $_header_mz = { 4D 5A }
    $msi_name = "update_ms.msi" ascii wide nocase
    $dll_name = "lib.dll" ascii wide nocase
    $export_run = "RUN" ascii wide fullword
    $bind_open = "msaOpen" ascii wide
    $bind_close = "msaClose" ascii wide
    $bind_error = "msaError" ascii wide
    $bind_message = "msaMessage" ascii wide
  condition:
    ($msi_name or $dll_name) and 2 of ($bind_open, $bind_close, $bind_error, $bind_message, $export_run)
}