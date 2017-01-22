#!/usr/local/bin/python
# -*- coding: utf-8 -*-


from helper import which, logger
from protocols import *
from certificates import *
import argparse
import sys

hostname=""
port=0
ca_file=""

def main(hostame, port, ca_file):
    #TODO: Commandline Arguments sind noch in Arbeit

    if which('openssl')==None:
        logger.errori('Could not find openssl in the path. Please install openssl and add it to the path. The call this script again. Will exit now.')
        exit (1)

    test_server_for_protocol(hostname,port)

    certs=read_certificates(hostname,port)
    check_leaf_certificate(certs[0])
    check_root_certificate(certs[-1])

    for crt in certs[1:-1]:
        check_intermediate_certificate(crt)

if __name__ == "__main__":
#TODO: Das Parsen der Parameter von der Kommandozeile könnte man schön machen.
    hostname=sys.argv[1] # Das ist der Server, der getestet werden soll
    port=sys.argv[2]  # und der zugehörige Port
    ca_file="/usr/local/etc/openssl/cert.pem" # Openssl greift auf diese Datei zu und erwartet alle gültigen Root-Zertifikate darin im PEM-Format

    main(hostname,port,ca_file)
