import "hash"

rule DarkCaracal_GoCaracal_Bandook_DelphiLoader_Aug2026_LATAM {
    meta:
        author = "detections.ai"
        description = "Detects known Dark Caracal GoCaracal, Bandook, and Delphi-loader payload files by SHA-256 hash from the August 2026 LATAM campaign reported by Arctic Wolf"
        actor = "Dark Caracal"

    condition:
        hash.sha256(0, filesize) == "1e499c815146124c4a6d2b48c99068b980ad74e1a2cfd16013f8d75a9425a0ca" or
        hash.sha256(0, filesize) == "77f7ad29f4a8037ee5f38d3d87fb91cfd97cb8f7fa7883edf3fce506df5200c0" or
        hash.sha256(0, filesize) == "8c03d072df2e1bf14b0c00a8ab99834138c8b69f301849bf09cb44394e916015" or
        hash.sha256(0, filesize) == "0a6da70548f14834acb8960689a589b48ff422f8385ae445a281aab77045fe22" or
        hash.sha256(0, filesize) == "a2cdf2fe741de4b13ad2298b387a6c32da4a94da180ae75bf8547386aee7376b"
}