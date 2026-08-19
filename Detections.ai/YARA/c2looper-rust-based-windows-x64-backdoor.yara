import "hash"

rule C2Looper_Rust_Backdoor {
    meta:
        author = "detections.ai"
        description = "Detects C2Looper Rust-based Windows x64 backdoor via debug strings, hardcoded filenames/paths, C2 endpoints, and known sample hashes"
    strings:
        $debug1 = "!!! v2 !!!" ascii wide
        $debug2 = "pongv2 from" ascii wide

        $dll1 = "wtsapi32.dll" ascii wide
        $dll2 = "winspool.drv" ascii wide

        $file1 = "c2_out.txt" ascii wide
        $file2 = "pld.exe" ascii wide
        $file3 = "cmd.json" ascii wide
        $file4 = "result.json" ascii wide
        $file5 = "beacon.json" ascii wide

        $api1 = "/api/beacon" ascii wide
        $api2 = "/api/result/" ascii wide

        $_mz = { 4D 5A }

    condition:
        $_mz at 0 and
        (
            hash.sha256(0, filesize) == "f96ff2f3abbff7f382ace509b90e54853b4b61c402ecde27d82f1c17b414867b" or
            hash.sha256(0, filesize) == "20675a659c338f7267fd09bacb431f4491f061d3acf42d07aca2dec3d25fa549" or
            hash.sha256(0, filesize) == "f59f32c9af4fa8a5dbd4668df8893593bc0c4324816cbf9b956acedcbfb8cdb6"
            or
            (2 of ($debug*) or 3 of ($dll*, $file*) or all of ($api*))
        )
}
