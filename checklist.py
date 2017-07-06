#!/usr/bin/python
# -*- coding: utf-8 -*-


from helper import which, logger, print_h1, print_h2
from server import Server
import argparse
import string
import ssl
import os,sys
# from tls_includes import *

def main(hostname, port, ca_file, clientcert_file, server_certificates, proxy, insecure):

    print_h1("Überprüfe Systemvorraussetzungen")
    if which('openssl')==None:
        logger.error('Could not find openssl in the path. Please install openssl and add it to the path. The call this script again. Will exit now.')
        exit (1)
    
    if server_certificates is None and proxy is not None:                       
        if ssl.OPENSSL_VERSION_NUMBER < 9999999999: # TODO: ab welcher version von openssl wird --proxy unterstuetz
            logger.error('Your version of OpenSSL does not support proxy setting. Please install OpenSSL x.x.x or later or try --servercertificates argument.')
            exit(1)
    

    if ca_file is not None:
        if os.path.exists(ca_file):
            logger.info("Using the following ca certificate file: "+ca_file)
        else:
            logger.error("ca file not found")
            sys.exit()
    else:
        logger.info("No dedicated ca_file provided. Using system ca.")

    if clientcert_file is not None:
        if os.path.exists(clientcert_file):
            logger.info("Using the following client certificate file: "+clientcert_file)
        else:
            logger.info("client certificate file not found.")
            sys.exit()

    if which('sslyze')==None:
        logger.error('Could not find sslyze in the path. Please install sslyze and add it to the path. The call this script again. Will exit now.')
        exit (1)


    svr=Server(hostname,port,ca_file,clientcert_file,server_certificates, split_proxy(proxy), insecure)

    svr.test_server_for_protocol()

    svr.read_certificates(server_certificates)

    if len(svr.certs)<1:
        logger.error("Zertifikate konnten nicht gelesen werden.")
        exit (1)

    svr.certs[0].check_leaf_certificate()

    if len(svr.certs)>1:
        svr.certs[-1].check_root_certificate()

    if len(svr.certs)>2:
        for crt in svr.certs[1:-1]:
            crt.check_intermediate_certificate()
            
def split_proxy(proxy, default_port=80):
    if proxy == None:
        return None    
    p = string.split(proxy, ':', 1)
    if 1 == len(p):
        p.append(default_port)
    return p[0], int(p[1])

if __name__ == "__main__":
    parser=argparse.ArgumentParser(description='Test a TLS server for compliance with TR 3116-4')
    parser.add_argument(dest='server', metavar='S', nargs=1, help='The server that should be tested')
    parser.add_argument(dest='port', metavar='P', nargs=1, help='The TLS port that the server speaks')
    parser.add_argument('--cafile',action="store", dest="cafile", help='Use this pem file carrying all the CAs that openssl uses for verification')
    parser.add_argument('--clientcertfile',action="store", dest="clientcertfile", help='Use this pem file carrying the client cert and key that openssl uses for client authentication')
    parser.add_argument('--servercertificates',action="store", dest="certs", help='Use the certificates in this file as the certificates presented by the server and do not akquire certificates directly.')
    parser.add_argument('--proxy',action="store", dest="proxy", help='Use http-proxy. Format proxyname:proxyport.')
    parser.add_argument('-k' , '--insecure',action="store_true", default=False, dest="insecure", help='do not verify certificate on connect')

    args=parser.parse_args()
    arguments=vars(args)

    main(arguments['server'][0],int(arguments['port'][0]),args.cafile, args.clientcertfile, args.certs, args.proxy, args.insecure)
