rule Xtreme
{
    meta:
        author = "Brian Wallace @botnet_hunter"
        author_email = "bwall@ballastsecurity.net"
        date = "2015-03-25"
        description = "Identify XtremeRat"
    strings:
        $s1 = "XTREME" wide
        $s2 = "XTREMEBINDER" wide
        $s3 = "DVCLAL" wide
        $s4 = "PACKAGEINFO" wide
        $s5 = "XTREMEUPDATE" wide
    condition:
        all of them
}