rule MAL_vbs_pwsh {
    meta:
        author = "evilcel3ri"
        date = "2025-01-09"
        daysOfYara = "4/100"

    strings:
        $a = "WinXRar" nocase
        $b = "powershell -inputformat" nocase
        $c = "cmd /c"
        $d = "Bootxr.exe" nocase

    condition:
        all of them
    }
