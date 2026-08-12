import "hash"

rule AMOS_Stealer_Loader_Known_Hashes {
    meta:
        author = "detections.ai"
        description = "Detects known malicious Mach-O stealer binaries (ARM64/x86_64) and associated Bash loader script by SHA256 hash"
    condition:
        hash.sha256(0, filesize) == "f0062f7e70e61493684a2f60748a475168e155bc2502163c844c42e87692abd0" or
        hash.sha256(0, filesize) == "619a99ba4ee9d7f33db8045c7e03c4265424977993fe8a53b0f45157c5abd3e5" or
        hash.sha256(0, filesize) == "5bad988affc1094f12b8b8bed659ef55b20e2988eb25441e1c1b34dd03b3eb52"
}