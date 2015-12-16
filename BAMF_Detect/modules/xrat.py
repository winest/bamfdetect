from common import Modules, load_yara_rules, PEParseModule, ModuleMetadata
from Crypto.Cipher import AES, XOR
import pefile
from base64 import b64decode
import re
import hashlib


class xRat(PEParseModule):
    first_value_table = None
    precomputed_list = None

    def __init__(self):
        md = ModuleMetadata(
            module_name="xrat",
            bot_name="xRat",
            description="RAT",
            authors=["Kevin Breen <kevin@techanarchy.net>", "Brian Wallace (@botnet_hunter)"],
            version="1.0.0",
            date="Aug 30, 2015",
            references=[
                "https://github.com/kevthehermit/YaraRules/blob/master/xRat.yar",
                "https://github.com/kevthehermit/RATDecoders/blob/master/xRat.py"
            ]
        )
        PEParseModule.__init__(self, md)
        self.yara_rules = None
        self.prng_seed = 0

    def _generate_yara_rules(self):
        if self.yara_rules is None:
            self.yara_rules = load_yara_rules("xrat.yara")
        return self.yara_rules

    @staticmethod
    def run_config_extraction(data):
        long_line, ver = xRat.get_long_line(data)
        print ver
        if ver is None:
            return None
        config_list = []
        if ver == 'V1':
            # The way the XOR Cypher was implemented the keys are off by 1.
            key1 = 'RAT11x'  # Used for First level of encryption actual key is 'xRAT11'
            key2 = 'eY11K'  # used for individual sections, actual key is 'KeY11'
            key3 = 'eY11PWD24K'  # used for password section only. Actual key is 'KeY11PWD24'
            config = long_line.decode('hex')
            first_decode = xRat.decrypt_XOR(key1, config)
            sections = first_decode.split('|//\\\\|')  # Split is |//\\| the extra \\ are for escaping.
            for i in range(len(sections)):
                if i == 3:
                    enc_key = key3
                else:
                    enc_key = key2
                config_list.append(xRat.decrypt_XOR(enc_key, sections[i].decode('hex')))
        if ver == 'V2':
            coded_lines = xRat.get_parts(long_line)
            enc_key = xRat.aes_key(coded_lines[-1])
            for i in range(1, (len(coded_lines) - 1)):
                decoded_line = b64decode(coded_lines[i])
                decrypt_line = xRat.decrypt_aes(enc_key, decoded_line)
                config_list.append(xRat.string_print(decrypt_line))
        return xRat.parse_config(config_list, ver)

    @staticmethod
    def string_print(line):
        return ''.join((char for char in line if 32 < ord(char) < 127))

    @staticmethod
    def parse_config(config_list, ver):
        config_dict = {}
        if ver == 'V1':
            config_dict['Version'] = '1.0.x'
            config_dict['Domain'] = config_list[1]
            config_dict['Port'] = config_list[2]
            config_dict['Password'] = config_list[3]
            config_dict['CampaignID'] = config_list[4]
            config_dict['InstallName'] = config_list[5]
            config_dict['HKCUKey'] = config_list[6]
            config_dict['InstallDir'] = config_list[7]
            config_dict['Flag1'] = config_list[8]
            config_dict['Flag2'] = config_list[9]
            config_dict['Mutex'] = config_list[10]

        if ver == 'V2':
            config_dict['Version'] = config_list[0]
            config_dict['Domain'] = config_list[1]
            config_dict['Password'] = config_list[2]
            config_dict['InstallSub'] = config_list[3]
            config_dict['InstallName'] = config_list[4]
            config_dict['Mutex'] = config_list[5]
            config_dict['RegistryKey'] = config_list[6]
        return config_dict

    @staticmethod
    def get_long_line(data):
        try:
            raw_config = None
            pe = pefile.PE(data=data)
            for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                if str(entry.name) == "RT_RCDATA":
                    new_dirs = entry.directory
                    for entry in new_dirs.entries:
                        if str(entry.name) == '0':
                            data_rva = entry.directory.entries[0].data.struct.OffsetToData
                            size = entry.directory.entries[0].data.struct.Size
                            data = pe.get_memory_mapped_image()[data_rva:data_rva + size]
                            raw_config = data
        except:
            raw_config = None

        if raw_config is not None:
            return raw_config, 'V1'
        try:
            m = re.search('\x69\x00\x6F\x00\x6E\x00\x00\x59(.*)\x6F\x43\x00\x61\x00\x6E', data)
            raw_config = m.group(0)[4:-12]
            return raw_config, 'V2'
        except:
            return None, None

    @staticmethod
    def decrypt_XOR(enckey, data):
        cipher = XOR.new(enckey)  # set the cipher
        return cipher.decrypt(data)  # decrpyt the data

    @staticmethod
    def decrypt_aes(enckey, data):
        iv = data[:16]
        cipher = AES.new(enckey, AES.MODE_CBC, iv)  # set the cipher
        return cipher.decrypt(data[16:])  # decrpyt the data

    @staticmethod
    def aes_key(enc_key):
        return hashlib.md5(enc_key).hexdigest().decode('hex')

    @staticmethod
    def get_parts(long_line):
        coded_config = []
        raw_line = long_line
        small_lines = raw_line.split('\x00\x00')
        for line in small_lines:
            if len(line) % 2 == 0:
                new_line = line[1:]
            else:
                new_line = line[2:]
            coded_config.append(new_line.replace('\x00', ''))
        return coded_config

    def get_bot_information(self, file_data):
        results = xRat.run_config_extraction(file_data)

        #  todo: This whole config parsing needs to be updated

        if results is None:
            return {}

        if "Domain" in results:
            c2s = []
            for i in [x for x in results['Domain'].split("|") if len(x.strip()) > 0]:
                c2s.append({"c2_uri": "tcp://{0}/".format(i)})

            results['t'] = c2s

        results = {}
        return results


Modules.list.append(xRat())