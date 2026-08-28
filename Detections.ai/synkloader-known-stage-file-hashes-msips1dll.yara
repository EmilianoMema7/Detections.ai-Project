import "hash"

rule SynkLoader_Known_Stage_File_Hashes {
    meta:
        author = "detections.ai"
        description = "Matches known SynkLoader stage components by SHA256 hash: MSI installer, ss.py Python loader, and msvcp150.dll fake runtime DLL"
    condition:
        hash.sha256(0, filesize) == "151d2a7f52f047638ca8ad80c859c6bfe04d7510fb10933817fa0e3ba5d07a11" or
        hash.sha256(0, filesize) == "d150c70d2732df17aa77991b9ebf4c896f044445e900978581d9598dfa5dc98c" or
        hash.sha256(0, filesize) == "61f961cfebdf9967844526649b4b75bba5b1b83210b70aa1bffe3f64e6ac3112"
}