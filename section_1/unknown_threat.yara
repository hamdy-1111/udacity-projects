rule UnknownThreat
{
    meta:
        description = "Detects the unique malware may affect other servers!!"
        author = "noopsaibot"  //noor eldin Elmenshawi
        date = "2024-08-06"
        version = "1.1"

    strings:
        $malware_string1 = "token.pH"
        
        $malware_string2 = "darkl0rd.com"

    condition:
        // Detect any of the unique strings
        $malware_string1 or $miner_string
}
