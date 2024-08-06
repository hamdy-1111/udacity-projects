rule UnknownThreat
{
    meta:
        description = "Detects the unique malware may affect other servers!!"
        author = "noopsaibot"  //noor eldin Elmenshawi
        date = "2024-08-06"
        version = "1.1"

    strings:
        // Unique string from ft32
        $malware_string1 = "token.pH"
        
        // Unique domain from wipefs
        $miner_string = "nicehash.com"

    condition:
        // Detect any of the unique strings
        $malware_string1 or $miner_string
}
