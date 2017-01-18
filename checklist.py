#!/usr/local/bin/python
# -*- coding: utf-8 -*-

import socket, ssl
import logging, logging.config, os, pem
import subprocess
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from tls_includes import cipher_suites


logger = logging.getLogger("TLS tester")
logger.setLevel(logging.INFO)

# create the logging file handler
fh = logging.FileHandler("/tmp/tls.log")
sh = logging.StreamHandler()

formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
fh.setFormatter(formatter)

# add handler to logger object
logger.addHandler(fh)
logger.addHandler(sh)

hostname='www.de-mail.t-online.de'

#Testing available protocols
protocols=[
[ssl.PROTOCOL_TLSv1, "TLSv1", False],
[ssl.PROTOCOL_TLSv1_1,"TLSv1.1", False],
[ssl.PROTOCOL_TLSv1_2,"TLSv1.2",True]]
logger.info("------------------------------------------------------------------------------------")
logger.info("Anforderung 2.3.1 Überpreufe die unterstuetzten Protokolle:")
logger.info("------------------------------------------------------------------------------------")
for protocol in protocols:
    try:
        context = ssl.SSLContext(protocol[0])
        context.verify_mode = ssl.CERT_REQUIRED
        context.check_hostname = True
        context.load_default_certs()

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ssl_sock = context.wrap_socket(s, server_hostname=hostname)

        ssl_sock.connect((hostname, 443))
        if protocol[2]:
            logger.info("Tested server does support " + protocol[1] + " This is the expected behavior")
        else:
            logger.error("Tested server does support " + protocol[1] + " This should not be the case")

    except ssl.SSLError as err:
        if "SSLV3_ALERT_HANDSHAKE_FAILURE" in err.args[1]:
            if not protocol[2]:
                logger.info("Tested server does not support " + protocol[1] + " This is the expected behavior")
            else:
                logger.error("Tested server does not support " + protocol[1] + " This should not be the case")

logger.info("------------------------------------------------------------------------------------")
logger.info("Anforderung 2.3.2/2.3.3 Überpreufe die unterstuetzten Cipher-Suites:")
logger.info("------------------------------------------------------------------------------------")
logger.info("Im Folgenden werden die vom Server unterstützten Cipher-Suites gelistet.")
logger.info("Diese müssen mit den Vorgaben der Checkliste abgeglichen werden.")
logger.info("Unerlaubte Cipher-Suites werden direkt markiert")


for cipher in cipher_suites:
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
        context.set_ciphers(cipher[1])
        context.verify_mode = ssl.CERT_REQUIRED
        context.check_hostname = True
        context.load_default_certs()

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ssl_sock = context.wrap_socket(s, server_hostname=hostname)
        ssl_sock.connect((hostname, 443))
        priority= ssl_sock.cipher()[2]
        print "hier"
        print ssl_sock.cipher()

        if cipher[2]:
            logger.info("Tested server does support " + cipher[0] + " with priority " + str(priority) + ". Please check with checklist whether this is appropiate for the current system.")
        else:
            logger.error("Tested server does support unallowed " + cipher[0] + " with priority " + str(priority) +  " This should not be the case")

        logger.info( "Tested server does support " + cipher[0])

    except ssl.SSLError as err:
        if "SSLV3_ALERT_HANDSHAKE_FAILURE" in err.args[1]:
                if not cipher[2]:
                    logger.info("Tested server does not support " + cipher[0] + " Please check with checklist")




# Todo: 2.4.1 Die verwendeten ephemeren Parameter waￌﾈhrend des TLS-Handshakes bieten ausreichende Sicherheit:

logger.info("------------------------------------------------------------------------------------")
logger.info("Anforderung 2.5.1 Überpruefe Session Renegotiation")
logger.info("------------------------------------------------------------------------------------")

openssl_cmd_getcert=" echo "R" | openssl s_client -connect "+ hostname +":443"
proc = subprocess.Popen([openssl_cmd_getcert], stdout=subprocess.PIPE, shell=True)
(out, err) = proc.communicate()
print out

if "Secure Renegotiation IS supported" in out:
    logger.error("Server supports secure renegotiation based on an extension. This shold not be the case")
else:
    logger.info("Server does not support secure renegotiation based on an extension. This is the expected behavior")

lines=out.split('\n')
if "handshake failure" in lines[-1]:
    logger.info("Server does not support insecure renegotiation. This is the expected behavior")
else:
    logger.error("Server supports insecure renegotiation. This shold not be the case")




try:

    openssl_cmd_getcert="echo 'Q' | openssl s_client -connect www.google.de:443 -showcerts  | sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p'"
    proc = subprocess.Popen([openssl_cmd_getcert], stdout=subprocess.PIPE, shell=True)
    (out, err) = proc.communicate()

    certs = pem.parse(out)

    for entry in certs:
        cert = x509.load_pem_x509_certificate(str(entry).encode('ascii','ignore'), default_backend())
        print cert.serial_number
        print cert.subject
        print cert.issuer
        print cert.signature_hash_algorithm
        print cert.signature_algorithm_oid
        print cert.public_key()
        print cert.extensions


except Exception as err:
    print err
    # if "SSLV3_ALERT_HANDSHAKE_FAILURE" in err.args[1]:
    #     logger.info( "Tested server does not support " + cipher[1])
