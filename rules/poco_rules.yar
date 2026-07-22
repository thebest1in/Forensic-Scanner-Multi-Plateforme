// ============================================================
// POCO X6 PRO FORENSIC SCANNER — YARA RULES v2.0
// Sources: MVT (Amnesty Tech), Yara-Rules project, custom
// ============================================================

// --- ORIGINAL RULES (TUNED) ---

rule Disguised_Suspicious_Package : disguised_package stalkerware {
    meta:
        description = "Detects suspicious packages masquerading as system updates or spyware"
        severity = "high"
        aggregate_policy = "contextual_validation_required"
    strings:
        $pkg1 = "com.android.sys.update.co" ascii nocase
        $pkg2 = "com.mspy.lite" ascii nocase
        $pkg3 = "com.spy.tracker" ascii nocase
        $pkg4 = "com.android.service.update" ascii nocase
        $pkg5 = "com.google.service.helper" ascii nocase
        $pkg6 = "com.xiaomi.system.update.service" ascii nocase
        $pkg7 = "com.android.packageinstaller.helper" ascii nocase
        $pkg8 = "com.mspy.pro" ascii nocase
        $pkg9 = "com.cerberus" ascii nocase
        $pkg10 = "com.flexispy" ascii nocase
        $pkg11 = "com.spybubble" ascii nocase
        $pkg12 = "com.mobilespy" ascii nocase
    condition:
        any of them
}

rule Pegasus_Zero_Click_Traces : pegasus zero_click apt {
    meta:
        description = "Detects traces of Pegasus or zero-click exploitation frameworks"
        severity = "critical"
    strings:
        $p1 = "libwebrtc_peg" ascii
        $p2 = "pegasus" ascii nocase
        $p3 = "FLEXISPY" ascii
        $p4 = "com.cerberus" ascii
        $p5 = "BFKit" ascii
        $p6 = "privilege_escalation" ascii nocase
        $p7 = "root_exploit" ascii nocase
        $p8 = "shellcode" ascii nocase
        $p9 = "proc/self/exe" ascii
        $cve = /CVE-20(2[1-9]|[3-9]\d)-\d{5,}/ ascii
        $data_dir = "/data/local/tmp/" ascii
    condition:
        any of ($p*) or ($cve and $data_dir)
}

rule Reverse_Shell_Indicators : reverse_shell c2 {
    meta:
        description = "Detects reverse shell tunneling services and C2 infrastructure"
        severity = "critical"
    strings:
        $rs1 = ".ngrok.io" ascii nocase
        $rs2 = ".duckdns.org" ascii nocase
        $rs3 = ".serveo.net" ascii nocase
        $rs4 = ".localtunnel.me" ascii nocase
        $rs5 = ".pipedream.net" ascii nocase
        $rs6 = ".burpcollaborator.net" ascii nocase
        $rs7 = ".oast.fun" ascii nocase
        $rs8 = ".oast.pro" ascii nocase
        $rs9 = ".canarytokens.com" ascii nocase
        $cmd1 = "bash -i" ascii
        $cmd2 = "/dev/tcp/" ascii
        $cmd3 = "nc -e " ascii
        $cmd4 = "ncat -e " ascii
        $cmd5 = "msfconsole" ascii nocase
    condition:
        any of ($rs*) or 2 of ($cmd*)
}

rule Suspicious_Battery_Consumption : spyware battery_drain {
    meta:
        description = "Detects indicators of background spyware consuming battery resources"
        severity = "medium"
        aggregate_policy = "contextual_only"
    strings:
        $b1 = "WAKE_LOCK" ascii
        $b2 = "foreground service" ascii nocase
        $b3 = "persistent" ascii nocase
        $b4 = "boot_completed" ascii
        $b5 = "RECEIVE_BOOT_COMPLETED" ascii
        $b6 = "android.permission.SYSTEM_ALERT_WINDOW" ascii
        $b7 = "device_admin" ascii nocase
    condition:
        $b6 and $b7 and $b3 and 2 of ($b1, $b2, $b4, $b5)
}

rule Suspicious_Network_Patterns : network data_exfil {
    meta:
        description = "Detects suspicious network activity on non-standard ports"
        severity = "medium"
        aggregate_policy = "contextual_validation_required"
    strings:
        $conn1 = /(ESTABLISHED|SYN_SENT)[^\r\n]{0,200}([0-9]{1,3}\.){3}[0-9]{1,3}:(4444|9999|31337)(\s|$)/ ascii
        $conn2 = /([0-9]{1,3}\.){3}[0-9]{1,3}:(4444|9999|31337)[^\r\n]{0,200}(ESTABLISHED|SYN_SENT)/ ascii
    condition:
        any of them
}

// --- MVT / AMNESTY TECH RULES ---

rule NoviSpy_Android_AccessibilityService : novispy android apt {
    meta:
        description = "Serbian NoviSpy Android spyware - accessibility service variant"
        author = "Donncha O Cearbhaill, Amnesty International"
        severity = "critical"
    strings:
        $c2_1 = "195.178.51.251" ascii
        $c2_2 = "79.101.110.108" ascii
        $c2_3 = "188.93.127.34" ascii
        $u_1 = "kataklinger vibercajzna" ascii nocase
        $u_2 = "6FDF20EAFA2D58AF609C72AE7092BB45" ascii nocase
        $u_3 = "ucitavanjepodataka" ascii nocase
        $s_1 = "MyAccessibilityService" ascii
        $s_2 = "change type content description" ascii
        $s_3 = "window state changed" ascii
        $s_4 = "notification state changed" ascii
        $s_5 = "imei=%s;imsi=%s;phone=%s;sim_serial=%s" ascii
    condition:
        any of ($c2*) or any of ($u*) or 3 of ($s*)
}

rule NoviSpy_Android_ServServices : novispy android apt {
    meta:
        description = "Serbian NoviSpy Android spyware - com.serv.services variant"
        author = "Donncha O Cearbhaill, Amnesty International"
        severity = "critical"
    strings:
        $c2 = "178.220.122.57" ascii
        $cmd1 = "CALL_REC_ON" ascii
        $cmd2 = "CHARGING_REC_ON" ascii
        $cmd3 = "SECURE_REC_ON" ascii
        $cmd4 = "SSD_MOBILE_ON" ascii
        $cmd5 = "UPLOAD_MOBILE_ON" ascii
        $cmd6 = "START_AUDIO" ascii
        $cmd7 = "WIFI_LOCK_ON" ascii
        $cmd8 = "AUTO_WIFI_ON" ascii
    condition:
        $c2 or 5 of ($cmd*)
}

rule FinSpy_Android_Config : finspy android apt {
    meta:
        description = "FinFisher FinSpy Android configuration in APK"
        author = "Esther Onfroy (U+039b), Amnesty Tech"
        severity = "critical"
    strings:
        $config_1 = { 90 5b fe 00 }
        $config_2 = { 70 37 80 00 }
        $config_3 = { 40 38 80 00 }
        $config_4 = { a0 33 84 }
        $config_5 = { 90 79 84 00 }
    condition:
        $config_1 and $config_2 and $config_3 and $config_4 and $config_5
}

rule Dendroid_RAT : android rat {
    meta:
        description = "Dendroid Android Remote Access Trojan"
        author = "Yara-Rules project"
        severity = "critical"
    strings:
        $s1 = "/upload-pictures.php?" ascii
        $s2 = "Opened Dialog:" ascii
        $s3 = "com/connect/MyService" ascii
        $s4 = "DroidianService" ascii
        $s5 = "ServiceReceiver" ascii
    condition:
        3 of them
}

rule HackingTeam_Android_Implant : hackingteam android apt {
    meta:
        description = "HackingTeam Android surveillance implant v4-v7"
        author = "Tim Strazzere"
        severity = "critical"
    strings:
        $settings = { 00 24 4C 63 6F 6D 2F 67 6F 6F 67 6C 65 2F 61 6E 64 72 6F 69 64 2F 67 6C 6F 62 61 6C 2F 53 65 74 74 69 6E 67 73 3B 00 }
        $getSms = { 00 12 67 65 74 53 6D 73 49 6E 70 75 74 4E 75 6D 62 65 72 73 00 }
    condition:
        $settings and $getSms
}

rule SandroRAT : sandrorat android rat {
    meta:
        description = "SandroRAT Android Remote Access Trojan"
        author = "Jacob Soo Lead Re"
        severity = "critical"
    strings:
        $a = "net.droidjack.server" ascii nocase
        $b = "SandroRat" ascii nocase
        $c = "com.droidjack" ascii nocase
    condition:
        any of them
}

// --- ADVANCED SPYWARE / CREDENTIAL THEFT ---

rule Android_Credential_Harvester : credential_theft {
    meta:
        description = "Detects patterns of credential harvesting on Android"
        severity = "high"
        aggregate_policy = "contextual_only"
    strings:
        $c1 = "getPassword" ascii
        $c2 = "account_password" ascii nocase
        $c3 = "wifi_password" ascii nocase
        $c4 = "KeyStore" ascii
        $d1 = "READ_SMS" ascii
        $d2 = "READ_CONTACTS" ascii
        $d3 = "READ_CALL_LOG" ascii
        $d4 = "READ_PHONE_STATE" ascii
        $d5 = "GET_ACCOUNTS" ascii
        $d6 = "RECORD_AUDIO" ascii
    condition:
        2 of ($c*) and 3 of ($d*)
}

rule Android_Data_Exfiltration : data_exfil {
    meta:
        description = "Detects data exfiltration patterns in Android logs"
        severity = "high"
        aggregate_policy = "contextual_validation_required"
    strings:
        $e1 = "upload" ascii nocase
        $e2 = "POST" ascii
        $e3 = "multipart" ascii nocase
        $e4 = "base64" ascii nocase
        $e5 = "/sdcard/" ascii
        $e6 = ".zip" ascii
        $e7 = "tar " ascii
        $e8 = "curl " ascii
        $e9 = "wget " ascii
    condition:
        4 of them
}

rule Android_Root_Detection_Evasion : root_evasion {
    meta:
        description = "Detects root detection evasion techniques"
        severity = "medium"
        aggregate_policy = "contextual_validation_required"
    strings:
        $r1 = "test-keys" ascii
        $r2 = "ro.debuggable" ascii
        $r3 = "/system/app/Superuser.apk" ascii nocase
        $r4 = "/system/bin/su" ascii
        $r5 = "com.noshufou.android.su" ascii nocase
        $r6 = "com.koushikdutta.superuser" ascii nocase
        $r7 = "eu.chainfire.supersu" ascii nocase
        $r8 = "com.topjohnwu.magisk" ascii nocase
    condition:
        3 of them
}

// --- HOOKING FRAMEWORK DETECTION ---

rule Frida_Hooking_Framework : frida hooking_framework {
    meta:
        description = "Detects Frida dynamic instrumentation framework"
        severity = "critical"
    strings:
        $f1 = "frida" ascii nocase
        $f2 = "frida-agent" ascii nocase
        $f3 = "frida-server" ascii nocase
        $f4 = "re.frida.server" ascii nocase
        $f5 = "frida-gadget" ascii nocase
        $f6 = "libfrida" ascii nocase
        $f7 = "frida_inject" ascii nocase
        $f8 = "FRIDA" ascii
    condition:
        2 of them
}

rule Xposed_Framework : xposed hooking_framework {
    meta:
        description = "Detects Xposed Framework for runtime modification"
        severity = "critical"
    strings:
        $x1 = "XposedBridge" ascii nocase
        $x2 = "de.robv.android.xposed" ascii nocase
        $x3 = "xposed_installer" ascii nocase
        $x4 = "XposedBridge.jar" ascii nocase
        $x5 = "libxposed" ascii nocase
        $x6 = "xposed_art" ascii nocase
        $x7 = "XSharedPreferences" ascii nocase
    condition:
        2 of them
}

rule Magisk_Root_Tool : magisk root {
    meta:
        description = "Detects Magisk Android root solution"
        severity = "high"
    strings:
        $m1 = "magisk" ascii nocase
        $m2 = "com.topjohnwu.magisk" ascii nocase
        $m3 = "/data/adb/magisk" ascii nocase
        $m4 = "/data/adb/.magisk" ascii nocase
        $m5 = "magiskhide" ascii nocase
        $m6 = "magiskpolicy" ascii nocase
        $m7 = "Zygisk" ascii nocase
    condition:
        2 of them
}

rule Substrate_Hooking : substrate hooking_framework {
    meta:
        description = "Detects Cydia Substrate / MobileSubstrate hooking framework"
        severity = "critical"
    strings:
        $s1 = "substrate" ascii nocase
        $s2 = "MobileSubstrate" ascii nocase
        $s3 = "libsubstrate" ascii nocase
        $s4 = "MSHookFunction" ascii
        $s5 = "MSHookMessageEx" ascii
        $s6 = "SubstrateLoader" ascii nocase
    condition:
        2 of them
}

rule Android_Spyware_Packages : spyware stalkerware {
    meta:
        description = "Detects known commercial spyware packages"
        severity = "critical"
    strings:
        $sp1 = "com.flexispy" ascii nocase
        $sp2 = "com.spyera" ascii nocase
        $sp3 = "com.mspy" ascii nocase
        $sp4 = "com.highster" ascii nocase
        $sp5 = "com.thetruthspy" ascii nocase
        $sp6 = "com.springsolutions" ascii nocase
        $sp7 = "com.androidstudioprojects" ascii nocase
        $sp8 = "com.widdit" ascii nocase
        $sp9 = "com.luxferre" ascii nocase
        $sp10 = "com.surqs" ascii nocase
        $sp11 = "com.fouadware" ascii nocase
        $sp12 = "com.hawk.android" ascii nocase
        $sp13 = "com.venum" ascii nocase
        $sp14 = "com.phonesheriff" ascii nocase
        $sp15 = "com.retina.je" ascii nocase
        $sp16 = "com.pretulian.spyphone" ascii nocase
        $sp17 = "com.childparental" ascii nocase
        $sp18 = "com.bkphone" ascii nocase
        $sp19 = "com.willdev" ascii nocase
        $sp20 = "com.android.systemapp" ascii nocase
    condition:
        any of them
}

rule Android_Remote_Access : remote_access rat {
    meta:
        description = "Detects remote access tools and RATs"
        severity = "high"
    strings:
        $ra1 = "com.anydesk.anydeskandroid" ascii nocase
        $ra2 = "com.teamviewer" ascii nocase
        $ra3 = "com.logmein" ascii nocase
        $ra4 = "com.splashtop" ascii nocase
        $ra5 = "com.realvnc" ascii nocase
        $ra6 = "net.droidjack.server" ascii nocase
        $ra7 = "com.droidjack" ascii nocase
        $ra8 = "com.sandrorat" ascii nocase
    condition:
        any of them
}

rule Android_Data_Exfiltration_Patterns : data_exfil {
    meta:
        description = "Detects data exfiltration patterns in Android system dumps"
        severity = "high"
        aggregate_policy = "contextual_validation_required"
    strings:
        $ex1 = "SEND_SMS" ascii
        $ex2 = "READ_SMS" ascii
        $ex3 = "READ_CONTACTS" ascii
        $ex4 = "READ_CALL_LOG" ascii
        $ex5 = "RECORD_AUDIO" ascii
        $ex6 = "CAMERA" ascii
        $ex7 = "ACCESS_FINE_LOCATION" ascii
        $ex8 = "READ_PHONE_STATE" ascii
        $ex9 = "WRITE_EXTERNAL_STORAGE" ascii
        $ex10 = "INSTALL_PACKAGES" ascii
        $ex11 = "SYSTEM_ALERT_WINDOW" ascii
        $ex12 = "BIND_ACCESSIBILITY_SERVICE" ascii
        $ex13 = "BIND_DEVICE_ADMIN" ascii
    condition:
        6 of them
}

rule Android_Security_Evasion : security_evasion {
    meta:
        description = "Detects security evasion and anti-analysis techniques"
        severity = "high"
    strings:
        $ev1 = "isDebugged" ascii
        $ev2 = "isRooted" ascii
        $ev3 = "isEmulator" ascii
        $ev4 = "isFridaRunning" ascii
        $ev5 = "detectFrida" ascii
        $ev6 = "checkXposed" ascii
        $ev7 = "bypassDetection" ascii
        $ev8 = "antiAnalysis" ascii
        $ev9 = "com.secure.android" ascii
        $ev10 = "SafetyNet" ascii nocase
    condition:
        3 of them
}
