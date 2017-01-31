#!/usr/local/bin/python
# -*- coding: utf-8 -*-


from helper import which, logger
from server import Server
from certificate import Certificate
import argparse
import sys
from tls_includes import *


def main(hostname, port, ca_file, server_certificates):
    if which('openssl')==None:
        logger.error('Could not find openssl in the path. Please install openssl and add it to the path. The call this script again. Will exit now.')
        exit (1)

    if which('sslyze')==None:
        logger.error('Could not find sslyze in the path. Please install sslyze and add it to the path. The call this script again. Will exit now.')
        exit (1)


    svr=Server(hostname,port,ca_file,server_certificates)

    svr.test_server_for_protocol()

    svr.read_certificates(server_certificates)

    print len(svr.certs)
    svr.certs[0].check_leaf_certificate()

    if len(svr.certs)>1:
        svr.certs[-1].check_root_certificate()

    if len(svr.certs)>2:
        for crt in svr.certs[1:-1]:
            crt.check_intermediate_certificate()

if __name__ == "__main__":
#TODO: Das Parsen der Parameter von der Kommandozeile könnte man schön machen.
    parser=argparse.ArgumentParser(description='Test a TLS server for compliance with TR 3116-4')
    parser.add_argument(dest='server', metavar='S', nargs=1, help='The server that should be tested')
    parser.add_argument(dest='port', metavar='P', nargs=1, help='The TLS port that the server speaks')
    parser.add_argument('--cafile',action="store", dest="cafile", help='Use this pem file carrying all the CAs that openssl uses for verification')
    parser.add_argument('--servercertificates',action="store", dest="certs", help='Use the certificates in this file as the certificates presented by the server and do not akquire certificates directly.')

    args=parser.parse_args()
    arguments=vars(args)

    global ca_file

    if args.cafile is None:
        logger.info("No dedicated ca_file provided. Using default vaule.")
        ca_file="/usr/local/etc/openssl/cert.pem"
    else:
        ca_file=args.cafile


    logger.info("Using the follwing ca_file: "+ca_file)


    main(arguments['server'][0],int(arguments['port'][0]),ca_file, args.certs)
