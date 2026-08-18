import "pe"

rule bumblebee_msimg32_gibberish_metadata {
  meta:
    author = "detections.ai"
    description = "Detects BumbleBee loader side-loaded as msimg32.dll via dictionary-derived gibberish PE version-info fields and known builder File Version"
  strings:
    $_filename = "msimg32.dll" ascii wide nocase
    $fv = "6.295.250.3" ascii wide
  condition:
    pe.is_pe and
    $fv and
    for any i in (0..pe.number_of_version_infos - 1) : (
      pe.version_info_list[i].key == "Comments" or
      pe.version_info_list[i].key == "CompanyName" or
      pe.version_info_list[i].key == "FileDescription"
    )
}
