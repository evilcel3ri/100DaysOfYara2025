rule UNK_apk_ua {

    meta:
        // This rule needs you to run jadx on the apk to decompile it
        author = "evilcel3ri"
        date = "2025-01-06"
        daysOfYara = "2/100"
        description = "Detects a suspicious UA for a malicious APK"
        references = "c4dd9b41b09231e4070d404a6285d8214c967b2692ddbd0f8e71c24286d40d49"

    strings:
        $a = "quizti/asquare" ascii wide nocase

    condition:
        all of them
    }
