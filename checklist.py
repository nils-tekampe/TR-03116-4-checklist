#!/usr/local/bin/python
# -*- coding: utf-8 -*-


from helper import which, logger
from protocols import *
from certificates import *
import argparse
import sys
from tls_includes import *


def main(hostame, port, ca_file):
    if which('openssl')==None:
        logger.errori('Could not find openssl in the path. Please install openssl and add it to the path. The call this script again. Will exit now.')
        exit (1)

    test_server_for_protocol(hostname,port)

    certs=read_certificates(hostname,port)
    check_leaf_certificate(certs[0])
    if len(certs)>1:
        check_root_certificate(certs[-1])

    if len(certs)>2:
        for crt in certs[1:-1]:
            check_intermediate_certificate(crt)

if __name__ == "__main__":
#TODO: Das Parsen der Parameter von der Kommandozeile könnte man schön machen.
    hostname=sys.argv[1] # Das ist der Server, der getestet werden soll
    port=sys.argv[2]  # und der zugehörige Port
    main(hostname,int(port),ca_file)
