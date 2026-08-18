rule byovd_rwdrv_hlpdrv_driver_files {
  meta:
    author = "detections.ai"
    description = "Detects known vulnerable BYOVD driver files rwdrv.sys and hlpdrv.sys used to disable endpoint security via kernel-level access"
  strings:
    $driver1 = "rwdrv.sys" ascii wide nocase
    $driver2 = "hlpdrv.sys" ascii wide nocase
  condition:
    any of them
}