import hashlib
import json
import datetime
from binascii import hexlify, unhexlify
import pefile
import regex as re
import argparse
import logging
import traceback
import os
from arc4 import ARC4

def configure_logger(log_level):
    log_file = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'remcos_config_extractor.log')
    log_levels = {0: logging.ERROR, 1: logging.WARNING, 2: logging.INFO, 3: logging.DEBUG}
    log_level = min(max(log_level, 0), 3)  # Clamp to 0-3 inclusive
    logging.basicConfig(level=log_levels[log_level],
                        format='%(asctime)s - %(name)s - %(levelname)-8s %(message)s',
                        handlers=[
                            logging.FileHandler(log_file, 'a'),
                            logging.StreamHandler()
                        ])

class Extractor:
    
    def __init__(self, input_file, output_file=None):
        self.logger = logging.getLogger('Remcos Config Extractor')
        self.input_file = input_file
        self.output_file = output_file
        self.output_strings = []
        self.c2_regex = re.compile(r'(?:\S+\.)+\w+\:\d{2,5}')
        
        with open(self.input_file, 'rb') as fp:
            self.data = fp.read()
        
        # Calculate SHA-256 hash
        self.file_hash = hashlib.sha256(self.data).hexdigest()
        
        self.pe = pefile.PE(self.input_file, fast_load=False)

    def rc4_decrypt(self, key, ciphertext):
        """
        RC4 Decrypt Ciphertext
        """
        arc4 = ARC4(key)
        return arc4.decrypt(ciphertext)

    def extract_config(self):
        """
        Extract key length, key and config data from rsrc. Decrypt and print config
        """
        try:

            # Find Resource
            for rsrc in self.pe.DIRECTORY_ENTRY_RESOURCE.entries:
                for entry in rsrc.directory.entries:
                    if entry.name.__str__() == 'SETTINGS':
                        offset = entry.directory.entries[0].data.struct.OffsetToData
                        size = entry.directory.entries[0].data.struct.Size

            config_data = self.pe.get_memory_mapped_image()[offset:offset + size]

            # Extract Key Length
            key_len = config_data[0]

            # Extract RC4 Key
            rc4_key = config_data[1:key_len + 1]

            # Extract config ciphertext
            ciphertext = config_data[key_len + 1:]   

            # RC4 Decrypt 
            decrypted = self.rc4_decrypt(rc4_key, ciphertext)

            # Parse Config
            parsed = decrypted.decode('ascii', 'ignore').split('|')
           
            c2 = parsed[0][:-3]
            c2s = self.c2_regex.findall(c2)
            botnet = parsed[2]

            # Prepare JSON data
            json_data = {
                "malware_family": "Remcos",
                "botnet": botnet,
                "c2_servers": c2s,
                "file_name": os.path.basename(self.input_file),
                "sha256": self.file_hash,
                "analysis_timestamp": datetime.datetime.now().isoformat()
            }

        except Exception as e:
            self.logger.error(f"Extraction error for {self.input_file}: {str(e)}")
            # Prepare JSON error data
            json_data = {
                "file_name": os.path.basename(self.input_file),
                "sha256": self.file_hash,
                "analysis_timestamp": datetime.datetime.now().isoformat(),
                "error": "extraction error"
            }

        # Save JSON data to file
        json_output_file = self.output_file or f"{os.path.splitext(self.input_file)[0]}_config.json"
        with open(json_output_file, 'w') as json_file:
            json.dump(json_data, json_file, indent=4)
        
        # Print summary
        print(f"Configuration saved to {json_output_file}")
        print(json.dumps(json_data, indent=4))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Remcos Config Extractor')
    parser.add_argument('-v', '--verbose', action='count', default=0, 
        help='Increase verbosity. Can specify multiple times for more verbose output')
    parser.add_argument('files', nargs='+') 
    args = parser.parse_args()
    configure_logger(args.verbose)
    for file in args.files:
        try:
            extractor = Extractor(file)
            extractor.extract_config()
        except Exception as e:
            print(f'Exception initializing extractor for {file}:')
            print(traceback.format_exc())
