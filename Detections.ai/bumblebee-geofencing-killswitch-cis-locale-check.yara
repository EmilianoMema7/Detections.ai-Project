rule BumbleBee_CIS_Locale_Killswitch
{
    meta:
        author = "detections.ai"
        description = "Detects BumbleBee loader binaries containing hard-coded CIS-region locale strings and GetSystemDefaultLocaleName used for geofencing killswitch"

    strings:
        $api = "GetSystemDefaultLocaleName" ascii

        $loc1 = "ru-RU" wide
        $loc2 = "ru-BY" wide
        $loc3 = "uk-UA" wide
        $loc4 = "ru-KG" wide
        $loc5 = "ru-MD" wide
        $loc6 = "kk-KZ" wide
        $loc7 = "ky-KG" wide
        $loc8 = "uz-Cyrl" wide
        $loc9 = "uz-Cyrl-UZ" wide
        $loc10 = "uz-Latn" wide
        $loc11 = "uz-Latn-UZ" wide
        $loc12 = "az-Cyrl" wide
        $loc13 = "az-Cyrl-AZ" wide
        $loc14 = "az-Latn" wide
        $loc15 = "az-Latn-AZ" wide
        $loc16 = "ka-GE" wide
        $loc17 = "uk-UA" wide
        $loc18 = "tg-Cyrl" wide
        $loc19 = "tg-Cyrl-TJ" wide
        $loc20 = "tk-TM" wide
        $loc21 = "hy-AM" wide
        $loc22 = "be-BY" wide
        $loc23 = "lt-LV" wide
        $loc24 = "lv-LV" wide
        $loc25 = "ro-MD" wide
        $loc26 = "et-EE" wide

        $exit = "ExitProcess" ascii

    condition:
        $api and $exit and 10 of ($loc*)
}