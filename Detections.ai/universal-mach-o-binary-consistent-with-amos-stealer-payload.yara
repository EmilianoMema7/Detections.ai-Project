rule amos_universal_macho_payload {
  meta:
    author = "detections.ai"
    description = "Detects a universal (fat) Mach-O binary containing both x86_64 and arm64 architecture slices, consistent with the final-stage payload delivered in the fake OpenAI Codex ClickFix campaign associated with Atomic macOS Stealer (AMOS)"
  strings:
    $_fat_magic_be = { CA FE BA BE }
    $_fat_magic_le = { BE BA FE CA }
    $cputype_x86_64 = { 01 00 00 07 }
    $cputype_arm64 = { 01 00 00 0C }
  condition:
    ($_fat_magic_be at 0 or $_fat_magic_le at 0) and
    $cputype_x86_64 in (0..256) and
    $cputype_arm64 in (0..256) and
    filesize > 500KB and filesize < 20MB
}