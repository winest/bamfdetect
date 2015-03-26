rule njrat{
    meta:
        author = "Brian Wallace @botnet_hunter"
        author_email = "bwall@ballastsecurity.net"
        date = "2015-03-21"
        description = "Identify njRat"
    strings:
        $str1 = "Execute ERROR" wide
        $str2 = "cmd.exe /c ping 127.0.0.1 & del" wide
        $str3 = "[ENTER]" wide
    condition:
        all of them
}