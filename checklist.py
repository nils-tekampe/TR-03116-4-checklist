#!/usr/local/bin/python
# -*- coding: utf-8 -*-

import socket, ssl
import logging, logging.config, os, pem
import subprocess
from cryptography import x509
from cryptography.x509 import Certificate
from cryptography.hazmat.backends import default_backend
from tls_includes import cipher_suites
import colorlog
from helper import which, logger
from protocols import *
from certificates import *

hostname='www.de-mail.t-online.de'
port=443

def main():
    if which('openssl')==None:
        logger.errori('Could not find openssl in the path. Please install openssl and add it to the path. The call this script again. Will exit now.')
        exit (1)

    # test_supported_protocols(hostname, port)
    # test_supported_cipher_suites(hostname,port)
    # test_session_renegotiation(hostname,port )
    # test_tls_compression(hostname,port)
    # test_heartbeat_extension(hostname,port)
    # TODO 2.4.1 Die verwendeten ephemeren Parameter waￌﾈhrend des TLS-Handshakes bieten ausreichende Sicherheit:

    certs=read_certificates(hostname,port)
    # check_certificate_key(certs[0])
    # check_signature_algorithm(certs[0])
    # check_for_wildcards(certs[0])
    # check_cert_for_crl(certs[0])
    # check_cert_for_aia(certs[0])
    # check_cert_for_revocation(certs[0])
    # check_cert_for_keyusage(certs[0])
    check_cert_for_extended_keyusage(certs[0])

if __name__ == "__main__":
    main()
