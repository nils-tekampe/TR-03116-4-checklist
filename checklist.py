#!/usr/local/bin/python
# -*- coding: utf-8 -*-

import socket, ssl
import logging, logging.config, os, pem
import subprocess
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from tls_includes import cipher_suites
import colorlog
from helper import which, logger
from protocols import *
from certificates import *

hostname='www.de-mail.t-online.de'
port=443

if which('openssl')==None:
    logger.error('Could not find openssl in the path. Please install openssl and add it to the path. The call this script again. Will exit now.')
    exit (1)

# test_supported_protocols(hostname, port)
# test_supported_cipher_suites(hostname,port)
# test_session_renegotiation(hostname,port )
# test_tls_compression(hostname,port)
# test_heartbeat_extension(hostname,port)
# TODO 2.4.1 Die verwendeten ephemeren Parameter waￌﾈhrend des TLS-Handshakes bieten ausreichende Sicherheit:

certs=read_certificates(hostname,port)
