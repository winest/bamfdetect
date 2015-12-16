from common import Modules, load_yara_rules, ELFParseModule, ModuleMetadata, data_strings
from Crypto.Cipher import AES, XOR
import pefile
from base64 import b64decode
import re
import hashlib


class XorDDoS(ELFParseModule):
    first_value_table = None
    precomputed_list = None

    def __init__(self):
        md = ModuleMetadata(
            module_name="xorddos",
            bot_name="XorDDoS",
            description="DDoSer",
            authors=["Brian Wallace (@botnet_hunter)"],
            version="1.0.0",
            date="Oct 07, 2015",
            references=[
                "http://blog.malwaremustdie.org/2014/09/mmd-0028-2014-fuzzy-reversing-new-china.html",
                "http://blog.malwaremustdie.org/2015/07/mmd-0037-2015-bad-shellshock.html"
            ]
        )
        ELFParseModule.__init__(self, md)
        self.yara_rules = None
        self.prng_seed = 0

    def _generate_yara_rules(self):
        if self.yara_rules is None:
            self.yara_rules = load_yara_rules("xorddos.yara")
        return self.yara_rules

    @staticmethod
    def decrypt_strirng(s):
        key = "BB2FA36AAA9541F0"
        r = ""
        for i in xrange(len(s)):
            k = chr(ord(s[i]) ^ ord(key[i % len(key)]))
            if k == "\x00":
                break
            r += k
        return r

    def get_bot_information(self, file_data):
        results = {}
        index = file_data.find('*6F6{\x1c\x19')
        if '*6F6{\x1c\x19' in file_data:
            results["config_uri"] = XorDDoS.decrypt_strirng(file_data[index:index + 1024])

        print [XorDDoS.decrypt_strirng("http://")]
        first_string = "rmfile="
        decrypted = []
        started = False
        for s in data_strings(file_data, min=1, charset="".join([chr(i) for i in xrange(1, 200)])):
            if s == first_string:
                started = True
                continue
            if started:
                if s == "/proc/%d/exe" or len(decrypted) > 12:
                    break
                if s[0] == "/" or s[0] == "%":
                    continue
                print [s]
                decrypted.append(XorDDoS.decrypt_strirng(s))

        print decrypted

        return results


Modules.list.append(XorDDoS())