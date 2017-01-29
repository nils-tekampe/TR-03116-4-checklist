#!/usr/local/bin/python
# -*- coding: utf-8 -*-


from helper import which, logger
from protocols import *
from certificates import *
import argparse
import sys
from tls_includes import *


def main(hostname, port, ca_file):
    print ca_file
    if which('openssl')==None:
        logger.error('Could not find openssl in the path. Please install openssl and add it to the path. The call this script again. Will exit now.')
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
    parser=argparse.ArgumentParser(description='Test a TLS server for compliance with TR 3116-4')
    parser.add_argument(dest='server', metavar='S', nargs=1, help='The server that should be tested')
    parser.add_argument(dest='port', metavar='P', nargs=1, help='The TLS port that the server speaks')
    parser.add_argument('--cafile',action="store", dest="cafile", help='Use this pem file carrying all the CAs that openssl uses for verification')
    parser.add_argument('--servercertificates',action="certs", dest="certs", help='Use the certificates in this file as the certificates presented by the server and do not akquire certificates directly.')

    args=parser.parse_args()
    arguments=vars(args)
    print arguments['cafile']

    ca_file=arguments['cafile'][0]
    main(arguments['server'][0],int(arguments['port'][0]),ca_file)
