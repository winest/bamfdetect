from BAMF_Detect.preprocessors.common import Preprocessor, Preprocessors
import hashlib


class HashingPreprocessor(Preprocessor):
    def __init__(self):
        Preprocessor.__init__(
            self,
            name="Hashes",
            author="Brian Wallace (@botnet_hunter)",
            date="March 14th, 2015",
            description="Computes hashes for each file",
            references="",
            version="1.0.0.0"
        )

    def _do_processing(self, file_data):
        to_return = {}
        to_return["sha256"] = hashlib.sha256(file_data).hexdigest()
        to_return["sha1"] = hashlib.sha1(file_data).hexdigest()
        to_return["md5"] = hashlib.md5(file_data).hexdigest()

        return to_return, file_data

Preprocessors.add_preprocessor(HashingPreprocessor())