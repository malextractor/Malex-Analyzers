import logging
import re
import string
from typing import Any, Dict, List
import json
from malduck import procmem, rc4
from malduck.extractor import Extractor
import os, subprocess
import hashlib
import datetime
 
log = logging.getLogger(__name__)


def pretty_print_config(config: List[bytes]) -> Dict[str, Any]:
    content = "\n".join(repr(x)[1:] for x in config)
    return {
        "in-blob": {"blob_name": "raw_cfg", "blob_type": "raw_cfg", "content": content}
    }


def brute_key(config: bytes) -> bytes:
    for match in re.findall(b"\x00(.*?)\x00", config):
        if config.count(match) in range(50, 60) and match not in (b".", b":"):
            return match

import os
import subprocess

# Extensions reconnues comme exécutables
EXECUTABLE_EXTENSIONS = ('.exe', '.bat', '.sh', '.py', '.bin', '.cmd')

def is_executable_via_file(file_path):
    """
    Utilise la commande `file` pour vérifier si un fichier est un exécutable.
    """
    try:
        result = subprocess.run(['file', file_path], capture_output=True, text=True)
        output = result.stdout.strip()
        return "executable" in output.lower(), output
    except Exception as e:
        return False, f"Erreur : {e}"

def list_files_with_checks():
    """
    Parcourt les fichiers du répertoire courant, identifie les exécutables
    via la commande `file` et par extension.
    """
    current_dir = os.getcwd()  # Répertoire courant
    
    for item in os.listdir(current_dir):
        full_path = os.path.join(current_dir, item)
        if os.path.isfile(full_path):
            # Vérifie avec la commande `file`
            is_exec, file_info = is_executable_via_file(full_path)
            
            # Vérifie avec l'extension
            has_exec_extension = item.lower().endswith(EXECUTABLE_EXTENSIONS)
            
            # Décision finale
            if is_exec or has_exec_extension:
                return full_path
            else:
                return None

def calculate_file_hash(filename):
    """
    Calcule le SHA-256 d'un fichier donné par son chemin.
    :param filename: Le chemin complet du fichier.
    :return: L'empreinte SHA-256 en hexadécimal.
    """
    if filename is not None:
        try:
            with open(filename, "rb") as file:
                sha256 = hashlib.sha256()
                # Lecture par blocs pour éviter les problèmes de mémoire avec de grands fichiers
                for chunk in iter(lambda: file.read(4096), b""):
                    sha256.update(chunk)
                return sha256.hexdigest()
        except FileNotFoundError:
            return "Fichier introuvable."
        except Exception as e:
            return f"Erreur : {e}"
    else:
        return "Chemin de fichier invalide ou None."

class Remcos(Extractor):
    yara_rules = ("win_remcos", "win_remcos_auto")
    family = "remcos"

    @Extractor.needs_pe
    @Extractor.final
    def get_config(self, p: procmem) -> None:
        filename = None
        hash_file = None        
        data = p.pe.resource("SETTINGS")

        if not data:
            log.error("SETTINGS resource not found or empty")
            return None

        log.info("got encrypted section")

        key_len = data[0]
        key = data[1:][:key_len]
        encrypted = data[1 + key_len :]
        decrypted = rc4(key, encrypted)
        #print(decrypted)
        split_key = brute_key(decrypted)

        if split_key is None:
            log.error("couldn't find split_key")
            return None

        log.info("got split_key")

        config_list = decrypted.split(split_key)
        C2_NEEDLES = [b"|", b"\xff\xff\xff\xff", b"\x1e"]

        c2s = [config_list[0].strip(b"\n")]
        for needle in C2_NEEDLES:
            if len(c2s) == 1 and c2s[0].count(needle) > 0:
                c2s = c2s[0].strip(needle).split(needle)

        log.info("found {num} c2s".format(num=len(c2s)))

        filename = list_files_with_checks()
        if filename is not None:
            filename = os.path.basename(filename)
            hash_file = calculate_file_hash(filename)


        config = {
            "malware_family": "Remcos",
            "file_name": filename,
            "c2_servers": [],
            "sha256": hash_file,
            "analysis_timestamp": datetime.datetime.now().isoformat(),
        }
        for c2 in c2s:
            host = b":".join(c2.split(b":")[:2])
            password = b":".join(c2.split(b":")[2:])

            c2_conf = {
                "host": host.decode("utf-8"),
            }

            if all(x in string.printable.encode() for x in password):
                c2_conf["password"] = password.decode("utf-8")

            config["c2_servers"].append(c2_conf)
        #print(config)
        print(json.dumps(config, indent=4))
        self.push_config(config)
        return None
