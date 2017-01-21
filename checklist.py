#!/usr/local/bin/python
# -*- coding: utf-8 -*-


from helper import which, logger
from protocols import *
from certificates import *

hostname='de-mail.gmx.net' # Das ist der Server, der getestet werden soll
port=443 # und der zugehörige Port
ca_file="/usr/local/etc/openssl/cert.pem" # Openssl greift auf diese Datei zu und erwartet alle gültigen Root-Zertifikate darin im PEM-Format

def main():
    if which('openssl')==None:
        logger.errori('Could not find openssl in the path. Please install openssl and add it to the path. The call this script again. Will exit now.')
        exit (1)

    test_server_for_protocol(hostname,port)
    certs=read_certificates(hostname,port)
    check_leaf_certificate(certs[0])

if __name__ == "__main__":
    main()
