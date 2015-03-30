from common import Modules, data_strings, load_yara_rules, PEParseModule, ModuleMetadata
import re
import zlib
from struct import unpack

from Crypto.Cipher import DES
import pefile


def run(raw_data):
    try:
        coded_config = get_codedconfig(raw_data)
        if coded_config[0:4] == '\x08\x00\x00\x00':
            config_dict = decrypt_new(coded_config)
        else:
           config_dict = decrypt_old(coded_config)
        return config_dict
    except KeyboardInterrupt:
        raise
    except:
        return


def decrypt_new(coded_config):
    key = coded_config[4:12]
    data = coded_config[16:]
    raw_config = decrypt_des(key, data)
    # if the config is over a certain size it is compressed. Indicated by a non Null byte
    if raw_config[1] == '\x00':
        return parse_config(raw_config, 'new')
    else:
        # remove the string lengths and deflate the remainder of the stream
        deflate_config = deflate_contents(raw_config)
        return parse_config(deflate_config, 'new')


def decrypt_old(coded_config):
    key = '\x01\x03\x05\x08\x0d\x15\x22\x37'
    data = coded_config[1:]
    new_data = decrypt_des(key, data)
    if new_data[0] != '\x00':
        deflate_config = deflate_contents(new_data)
        return parse_config(deflate_config, 'old')


def deflate_contents(data):
    new_data = data[5:]
    return zlib.decompress(new_data, -15)


# Returns only printable chars
def string_print(line):
    try:
        return ''.join((char for char in line if 32 < ord(char) < 127))
    except KeyboardInterrupt:
        raise
    except:
        return line


# returns pretty config
def parse_config(raw_config, ver):
    config_dict = {}
    if ver == 'new':
        #config_dict['BuildTime'] = unpack(">Q", re.search('BuildTime(.*?)\x0c', raw_config).group()[10:-1])[0]
        config_dict['Version'] = re.search('Version\x0c(.*?)\x0c', raw_config).group()[8:-1]
        config_dict['Mutex'] = re.search('Mutex(.*?)\x0c', raw_config).group()[6:-1].encode('hex')
        config_dict['Group'] = re.search('DefaultGroup\x0c(.*?)\x0c', raw_config).group()[14:-1]
        config_dict['Domain1'] = re.search('PrimaryConnectionHost\x0c(.*?)\x0c', raw_config).group()[23:-1]
        config_dict['Domain2'] = re.search('BackupConnectionHost\x0c(.*?)\x0c', raw_config).group()[22:-1]
        config_dict['Port'] = unpack("<H", re.search('ConnectionPort(.*?)\x0c', raw_config).group()[15:-1])[0]
        config_dict['RunOnStartup'] = re.search('RunOnStartup(.*?)\x0c', raw_config).group()[13:-1].encode('hex')
        config_dict['RequestElevation'] = re.search('RequestElevation(.*?)\x0c', raw_config).group()[17:-1].encode('hex')
        config_dict['BypassUAC'] = re.search('BypassUserAccountControl(.*?)\x0c', raw_config).group()[25:-1].encode('hex')
        config_dict['ClearZoneIdentifier'] = re.search('ClearZoneIdentifier(.*?)\x0c', raw_config).group()[20:-1].encode('hex')
        config_dict['ClearAccessControl'] = re.search('ClearAccessControl(.*?)\x0c', raw_config).group()[19:-1].encode('hex')
        config_dict['SetCriticalProcess'] = re.search('SetCriticalProcess(.*?)\x0c', raw_config).group()[19:-1].encode('hex')
        config_dict['FindLanServers'] = re.search('FindLanServers(.*?)\x0c', raw_config).group()[15:-1].encode('hex')
        config_dict['RestartOnException'] = re.search('RestartOnException(.*?)\x0c', raw_config).group()[19:-1].encode('hex')
        config_dict['EnableDebugMode'] = re.search('EnableDebugMode(.*?)\x0c', raw_config).group()[16:-1].encode('hex')
        config_dict['ConnectDelay'] = unpack("<i", re.search('ConnectDelay(.*?)\x0c', raw_config).group()[13:-1])[0]
    else:
        config_dict['Domain'] = re.search('HOST\x0c(.*?)\x0c', raw_config).group()[6:-1]
        config_dict['Port'] = unpack("<H", re.search('PORT(.*?)\x0c', raw_config).group()[5:-1])[0]
        config_dict['Group'] = re.search('GROUP\x0c(.*?)\x0c', raw_config).group()[7:-1]
        config_dict['ConnectDelay'] = unpack("<i", re.search('DELAY(.*?)\x0c', raw_config).group()[6:-1])[0]
        config_dict['OfflineKeyLog'] = str(re.search('OFFLINE_KEYLOGGING(.*?)\x0c', raw_config).group()[19:-1].encode('hex'))
    return config_dict


# This gets the encoded config from a stub
def get_codedconfig(data):

    coded_config = None
    pe = pefile.PE(data=data)
    for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        if str(entry.name) == "RC_DATA" or "RCData":
            new_dirs = entry.directory
            for res in new_dirs.entries:
                data_rva = res.directory.entries[0].data.struct.OffsetToData
                size = res.directory.entries[0].data.struct.Size
                data = pe.get_memory_mapped_image()[data_rva:data_rva+size]
                coded_config = data
                return coded_config


def decrypt_des(key, data):
    iv = key
    cipher = DES.new(key, DES.MODE_CBC, iv)
    return cipher.decrypt(data)


class Nanocore(PEParseModule):
    def __init__(self):
        md = ModuleMetadata(
            module_name="nanocore",
            bot_name="NanoCore",
            description="RAT",
            authors=["Brian Wallace (@botnet_hunter)"],
            version="1.0.0",
            date="March 27, 2015",
            references=[]
        )
        PEParseModule.__init__(self, md)
        self.yara_rules = None
        pass

    def _generate_yara_rules(self):
        if self.yara_rules is None:
            self.yara_rules = load_yara_rules("nanocore.yara")
        return self.yara_rules

    def get_bot_information(self, file_data):
        results = run(file_data)
        if results is None:
            results = {}
        if 'Port' in results and ('Domain' in results or 'Domain1' in results or 'Domain2' in results):
            results['c2s'] = []
            if 'Domain' in results:
                results['c2s'].append({"c2_uri": "tcp://{0}:{1}".format(results['Domain'], results['Port'])})
            if 'Domain1' in results and 'Port' in results:
                results['c2s'].append({"c2_uri": "tcp://{0}:{1}".format(results['Domain1'], results['Port'])})
            if 'Domain2' in results and 'Port' in results:
                results['c2s'].append({"c2_uri": "tcp://{0}:{1}".format(results['Domain2'], results['Port'])})

        return results


Modules.list.append(Nanocore())