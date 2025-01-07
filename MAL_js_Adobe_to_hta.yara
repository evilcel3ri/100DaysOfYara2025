rule MAL_js_Adobe_to_hta {
    meta:
        author = "evilcel3ri"
        date = "2025-01-07"
        daysOfYara = "3/100"
        description = "Detects a malicious JS file dropping a hta"
        references = "701435e822a78b82d53281af3ffb20b3732462ec99c6f36afdfc6f8eed4123f9"

        yarahub_license = "CC0 1.0"
        yarahub_reference_md5 = "e865de0263ada94ea596fce4efd89ad0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_uuid = "0D480793-0670-42E3-B1B6-022FD7816E0D"

    strings:
        $java = "java" ascii nocase
        $activex = "ActiveXObject" ascii nocase
        $a = "!![]"
        $b = "{}}}()));"
        $count_1 = "continue"
        $count_2 = "0x"

    condition:
        filesize > 300 and #count_1 > 20 and #count_2 > 20000 and $a and $b and $java and $activex
    }
