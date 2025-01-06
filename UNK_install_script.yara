rule UNK_install_script {
    meta:
        author = "evilcel3ri"
        date = "2025-01-06"
        daysOfYara = "1/100"
        description = "Detects a suspicious behaviour in an bash installation script"
        references = "37f62cfba226d05f914dfe017faf018d08f15e6c645fbbfc43c0c4f1212e68b3"

        yarahub_license = "CC0 1.0"
        yarahub_reference_md5 = "2022fa13f1a41a4152ea711d970a7ba3"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_uuid = "A38178E1-4C9F-4794-9925-2EE53168334C"

    strings:
        $a = "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://" nocase
        $b = "chmod 777"

    condition:
        #a > 10 and #b > 10
    }
