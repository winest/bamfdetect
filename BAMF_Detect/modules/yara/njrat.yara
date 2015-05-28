rule njrat{
    meta:
        author = "Brian Wallace @botnet_hunter"
        author_email = "bwall@ballastsecurity.net"
        date = "2015-05-27"
        description = "Identify njRat"
    strings:
        $s1 = "netsh firewall add allowedprogram " wide
        $s2 = " & exit" wide
        $s3 = "md.exe /k ping 0 & del " wide
        $s4 = "My.Computer"
        $s5 = "My.Application"
        $s6 = "8.0.0.0"
    condition:
        all of them
}