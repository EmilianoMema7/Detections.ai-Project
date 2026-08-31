rule targeted_DarkCaracal_GoCaracal_Lightweight_RAT {
  meta:
    author = "detections.ai"
    description = "Detects GoCaracal Lightweight RAT (Dark Caracal / GoCaracal Go-based implant) associated with LATAM campaign reported by Arctic Wolf, August 2026"
    tlp = "TLP:CLEAR"
    hash = "1E499C815146124C4A6D2B48C99068B980AD74E1A2CFD16013F8D75A9425A0CA"
    filename = "TF-OFICINA004A9.exe"
  strings:
    $s1 = "main.cleanupShell" ascii wide
    $s2 = "main.handleConnection" ascii wide
    $s3 = "main.detectAntivirus" ascii wide
    $s4 = "main.saveFile" ascii wide
    $s5 = "main.openUrl" ascii wide
    $s6 = "main.smartSleep" ascii wide
    $s7 = "main.runModule" ascii wide
    $s8 = "main.InjectShellcode" ascii wide
    $s9 = "main.injectShellcodeWoW64" ascii wide
    $s10 = "main.handlePipeClient" ascii wide
    $s11 = "insensate" ascii wide
    $s12 = "readSecurePacket" ascii wide
    $s13 = "main.loadAPIs" ascii wide
    $s14 = "SendSecurePacket" ascii wide
    $s15 = "getRawOSVersion" ascii wide
    $s16 = "RPCFallback" ascii wide
    $s17 = "main.AntivirusProduct" ascii wide
    $s18 = "main.lastInputInfo" ascii wide
  condition:
    5 of them
}
