rule PS_JPEG_Pixel_Steganography_Payload_Extraction
{
    meta:
        author = "detections.ai"
        description = "Detects PowerShell script content combining pixel/byte-array parsing logic with LSB or channel-extraction decoding and in-memory decryption terminology, consistent with steganographic payload extraction from JPEG pixel data"
    strings:
        $pixel = "pixel" nocase
        $bytearr = "byte" nocase
        $lsb = "LSB" nocase
        $channel = "channel" nocase
        $decrypt = "decrypt" nocase
        $memory = "memory" nocase
    condition:
        filesize < 5MB and $pixel and $bytearr and (any of ($lsb, $channel)) and $decrypt and $memory
}