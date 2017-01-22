#!/usr/local/bin/python
# -*- coding: utf-8 -*-


from helper import which, logger
from protocols import *
from certificates import *
import argparse

hostname='www.google.de' # Das ist der Server, der getestet werden soll
port=443 # und der zugehörige Port
ca_file="/usr/local/etc/openssl/cert.pem" # Openssl greift auf diese Datei zu und erwartet alle gültigen Root-Zertifikate darin im PEM-Format

#TODO: Commandline Arguments sind noch in Arbeit
parser=argparse.ArgumentParser(description="Dieses Skript testet einen TLS Server auf Konformität zur Checkliste der TR 03116-4")
parser.add_argument("server", type=str, help="Der zu testende Server")
parser.add_argument("port", type=int, help="Der Port des zu testenden Server")



def main():
    if which('openssl')==None:
        logger.errori('Could not find openssl in the path. Please install openssl and add it to the path. The call this script again. Will exit now.')
        exit (1)

    # test_server_for_protocol(hostname,port)

    logger.info("------------------------------------------------------------------------------------")
    logger.info("Rufe die Zertifkate für die weiteren Tests ab")
    logger.info("------------------------------------------------------------------------------------")
    certs=read_certificates(hostname,port)
    check_leaf_certificate(certs[0])
    check_root_certificate(certs[-1])

    for crt in certs[1:-1]:
        check_intermediate_certificate(crt)

if __name__ == "__main__":
    main()
