rule Spyware_Indicators {
    meta:
        description = "Detects common mobile spyware indicators"
        author = "Forensic Scanner Multi-Plateforme"
        severity = "critical"
    strings:
        $s1 = "flexispy" nocase
        $s2 = "mspy" nocase
        $s3 = "pegasus" nocase
        $s4 = "dendroid" nocase
        $s5 = "sandrorat" nocase
        $s6 = "hackingteam" nocase
        $s7 = "finspy" nocase
        $s8 = "novispy" nocase
        $s9 = "droidjack" nocase
        $s10 = "spyera" nocase
        $s11 = "highster" nocase
        $s12 = "mobistealth" nocase
    condition:
        any of them
}

rule Reverse_Shell {
    meta:
        description = "Detects reverse shell commands and patterns"
        author = "Forensic Scanner Multi-Plateforme"
        severity = "critical"
    strings:
        $r1 = /bash\s+-i\s+>&\s+\/dev\/tcp/
        $r2 = /nc\s+-[el]\s+/
        $r3 = /ncat\s+-[el]\s+/
        $r4 = /socat\s+/
        $r5 = /python.*socket.*connect/
        $r6 = /perl.*socket.*connect/
        $r7 = /ruby.*socket.*connect/
        $r8 = /php.*fsockopen/
    condition:
        any of them
}

rule Credential_Harvesting {
    meta:
        description = "Detects credential harvesting tools and techniques"
        author = "Forensic Scanner Multi-Plateforme"
        severity = "critical"
    strings:
        $c1 = "mimikatz" nocase
        $c2 = "lazagne" nocase
        $c3 = "procdump" nocase
        $c4 = "lsass" nocase
        $c5 = "comsvcs.dll" nocase
        $c6 = "sekurlsa" nocase
        $c7 = "kerberos" nocase
        $c8 = "credential" nocase
    condition:
        2 of them
}

rule Ransomware_Indicators {
    meta:
        description = "Detects ransomware-related artifacts"
        author = "Forensic Scanner Multi-Plateforme"
        severity = "critical"
    strings:
        $r1 = ".locked" nocase
        $r2 = ".encrypted" nocase
        $r3 = ".crypto" nocase
        $r4 = "ransom" nocase
        $r5 = "bitcoin" nocase
        $r6 = "wallet" nocase
        $r7 = "decrypt" nocase
        $r8 = "pay" nocase
    condition:
        3 of them
}

rule Process_Injection {
    meta:
        description = "Detects process injection techniques"
        author = "Forensic Scanner Multi-Plateforme"
        severity = "critical"
    strings:
        $i1 = "CreateRemoteThread" nocase
        $i2 = "VirtualAllocEx" nocase
        $i3 = "WriteProcessMemory" nocase
        $i4 = "NtCreateThreadEx" nocase
        $i5 = "RtlCreateUserThread" nocase
        $i6 = "inject" nocase
    condition:
        2 of them
}

rule Anti_Analysis {
    meta:
        description = "Detects anti-debugging and anti-analysis techniques"
        author = "Forensic Scanner Multi-Plateforme"
        severity = "suspicious"
    strings:
        $a1 = "IsDebuggerPresent" nocase
        $a2 = "CheckRemoteDebuggerPresent" nocase
        $a3 = "NtQueryInformationProcess" nocase
        $a4 = "OutputDebugString" nocase
        $a5 = "FindWindow" nocase
        $a6 = "anti-debug" nocase
        $a7 = "sandbox" nocase
    condition:
        2 of them
}

rule Lateral_Movement {
    meta:
        description = "Detects lateral movement tools and techniques"
        author = "Forensic Scanner Multi-Plateforme"
        severity = "critical"
    strings:
        $l1 = "psexec" nocase
        $l2 = "wmiexec" nocase
        $l3 = "smbexec" nocase
        $l4 = "evil-winrm" nocase
        $l5 = "crackmapexec" nocase
        $l6 = "lateral" nocase
    condition:
        2 of them
}
