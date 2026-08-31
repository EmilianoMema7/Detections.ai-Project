rule Poisoned_Claude_SKILL_MD_Hidden_Instructions {
    meta:
        author = "detections.ai"
        description = "Detects SKILL.md/markdown agent-skill files containing hidden-content constructs combined with command execution or download indicators, consistent with Aug 2026 Claude infostealer campaigns abusing poisoned agent-skill documents"

    strings:
        // (structure) doc looks like a skill/instruction markdown file
        $skill1 = "skill" nocase
        $skill2 = /^#+\s/
        $skill3 = "---" ascii

        // (a) hidden-text / comment constructs
        $hide1 = "<!--"
        $hide2 = "-->"
        $hide3 = /[\x{200B}\x{200C}\x{200D}\x{FEFF}]/
        $hide4 = "display:none" nocase
        $hide5 = "ignore previous instructions" nocase
        $hide6 = "ignore the above" nocase

        // (b) execution / download indicators
        $exec1 = "curl " nocase
        $exec2 = "wget " nocase
        $exec3 = "Invoke-WebRequest" nocase
        $exec4 = "iwr " nocase
        $exec5 = "irm " nocase
        $exec6 = "powershell -enc" nocase
        $exec7 = "powershell -e " nocase
        $exec8 = "base64 -d" nocase
        $exec9 = "base64 --decode" nocase

    condition:
        filesize < 5MB
        and 1 of ($skill*)
        and 1 of ($hide*)
        and 1 of ($exec*)
}
