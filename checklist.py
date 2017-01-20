#!/usr/local/bin/python
# -*- coding: utf-8 -*-

import socket, ssl
import logging, logging.config, os, pem
import subprocess
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from tls_includes import cipher_suites
import colorlog


logger = colorlog.getLogger("checklist.py")
logger.setLevel(logging.INFO)
sh = colorlog.StreamHandler()
# formatter = sh.setFormatter(colorlog.ColoredFormatter('%(log_color)s%(levelname)s:%(name)s:%(message)s'))
formatter = sh.setFormatter(colorlog.ColoredFormatter('%(log_color)s%(name)s:%(message)s'))
logger.addHandler(sh)


hostname='www.de-mail.t-online.de'
port=443

# Helper function to check for the availability of streamripper.
# Thanks to http://stackoverflow.com/questions/377017/test-if-executable-exists-in-python
def which(program):
    def is_exe(fpath):
        return os.path.isfile(fpath) and os.access(fpath, os.X_OK)

    fpath, fname = os.path.split(program)
    if fpath:
        if is_exe(program):
            return program
    else:
        for path in os.environ["PATH"].split(os.pathsep):
            path = path.strip('"')
            exe_file = os.path.join(path, program)
            if is_exe(exe_file):
                return exe_file


if which('openssl')==None:
    logger.error('Could not find openssl in the path. Please install openssl and add it to the path. The call this script again. Will exit now.')
    exit (1)


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

        ssl_sock.connect((hostname, port))
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
logger.info("Anforderung 2.3.2/2.3.3/2.3.4 Überpreufe die unterstuetzten Cipher-Suites:")
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
        ssl_sock.connect((hostname, port))
        priority= ssl_sock.cipher()[2]

        if cipher[2]:
            logger.warning(cipher[0] + " supported with priority " + str(priority) + ". Please check with checklist whether this is appropiate for the current system.")
        else:
            logger.error("Tested server does support unallowed " + cipher[0] + " with priority " + str(priority) +  " This should not be the case")

        logger.info( "Tested server does support " + cipher[0])

    except ssl.SSLError as err:
        if "SSLV3_ALERT_HANDSHAKE_FAILURE" in err.args[1]:
                if not cipher[2]:
                    logger.warning(cipher[0] + " not supported. Please check with checklist")


# TODO 2.4.1 Die verwendeten ephemeren Parameter waￌﾈhrend des TLS-Handshakes bieten ausreichende Sicherheit:

logger.info("------------------------------------------------------------------------------------")
logger.info("Anforderung 2.5.1 Überpruefe Session Renegotiation")
logger.info("------------------------------------------------------------------------------------")

openssl_cmd_getcert=" echo "R" | openssl s_client -connect "+ hostname +":"+str(port)
proc = subprocess.Popen([openssl_cmd_getcert], stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
(out, err) = proc.communicate()

if "Secure Renegotiation IS supported" in out:
    logger.error("Server supports secure renegotiation based on an extension. This shold not be the case")
else:
    logger.info("Server does not support secure renegotiation based on an extension. This is the expected behavior")
    logger.info("Now checking whehter classical renegotiation works")

lines=out.split('\n')
if "handshake failure" in lines[-1]:
    logger.info("Server does not support insecure renegotiation. This is the expected behavior")
else:
    logger.error("Server supports insecure renegotiation. This shold not be the case")

logger.info("------------------------------------------------------------------------------------")
logger.info("Anforderung 2.5.2 Überpruefe TLS Kompression")
logger.info("------------------------------------------------------------------------------------")
# Die Ausgabe von openssl aus Anforderung 2.5.1 enthält auch Informationen zur Komprimierung

if "Compression: NONE" in out:
    logger.info("Server does not support compression. This is the expected behavior")
else:
    logger.error("Server supports compression. This shold not be the case")

logger.info("------------------------------------------------------------------------------------")
logger.info("Anforderung 2.5.3 Überpruefe auf Heartbeat-Extension")
logger.info("------------------------------------------------------------------------------------")
#Thanks to  https://www.feistyduck.com/library/openssl-cookbook/online/ch-testing-with-openssl.html

openssl_cmd_getcert=" echo Q | openssl s_client -connect "+ hostname +":"+str(port)+" -tlsextdebug"
proc = subprocess.Popen([openssl_cmd_getcert], stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
(out, err) = proc.communicate()

if "heartbeat" in out:
    logger.error("Server supports the heartbeat extension. This shold not be the case")
else:
    logger.info("Server does not support the heartbeat extension. This is the intended behavior")

logger.info("------------------------------------------------------------------------------------")
logger.info("Anforderung 2.5.4 Überpruefe auf truncated_hmac-Extension")
logger.info("------------------------------------------------------------------------------------")
# Die Ausgabe von openssl aus Anforderung 2.5.3 enthält auch Informationen zu diese Extension

#TODO: wir brauchen mal einen Server mit einer truncated_hmac extension um zu sehen, ob das hier funktioniert.
if "truncated_hmac" in out:
    logger.error("Server supports the truncated_hmac extension. This shold not be the case")
else:
    logger.info("Server does not support the truncated_hmac extension. This is the intended behavior")
# --------------
logger.info("------------------------------------------------------------------------------------")
logger.info("We will no obtain the certificates for the later test cases")
logger.info("------------------------------------------------------------------------------------")
try:

    openssl_cmd_getcert="echo 'Q' | openssl s_client -connect "+ hostname +":"+str(port)+ " -showcerts  | sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p'"
    proc = subprocess.Popen([openssl_cmd_getcert], stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    (out, err) = proc.communicate()

    certs = pem.parse(out)

    logger.info(str(len(certs)) +" Certificates have been obtained.")

    for entry in certs:
        cert = x509.load_pem_x509_certificate(str(entry).encode('ascii','ignore'), default_backend())
        logger.info("Now checking certificate with serial: "+str(cert.serial_number))
        logger.info("Here come the attributes of the subject of the certificate:")
        for attribute in cert.subject:
            logger.info(attribute)

        logger.info("The signature algorithm of the certificate is: "+str(cert.signature_algorithm_oid))

        if type(cert.public_key()=="cryptography.hazmat.backends.openssl.rsa._RSAPublicKey"):
            logger.info("This certificate has an RSA key")
            # logger.info.("The key size is: "+str(cert.public_key().key_size)
        if type(cert.public_key()=="cryptography.hazmat.primitives.asymmetric.dsa.DSAPublicKey"):
            logger.error("This certificate has an DSA key. This should not be the case")
        if type(cert.public_key()=="cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKey"):
            logger.info("This certificate has an EllipticCurvePublicKey key")


        logger.info("The certificate contains the following extensions:")
        for extension in cert.extensions:
            logger.info(extension.oid)

        keyUsage=cert.extensions.get_extension_for_class(x509.KeyUsage)
        # print keyUsage
        # print type(keyUsage)
        logger.warning("The keyUsage extension contains:")
        logger.warning("digital_signature:"+str(keyUsage.value.digital_signature))
        logger.warning("key_cert_sign:"+str(keyUsage.value.key_cert_sign))
        logger.warning("crl_sign:"+str(keyUsage.value.crl_sign))

        extendedKeyUsage=cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
        logger.warning("The extendedKeyUsage extension contains:")
        logger.warning(extendedKeyUsage)

        # print cert.serial_number
        # print cert.subject
        # print cert.issuer
        # print cert.signature_hash_algorithm
        # print cert.signature_algorithm_oid
        # print cert.public_key()
        # print cert.extensions




except Exception as err:
    print err
    # if "SSLV3_ALERT_HANDSHAKE_FAILURE" in err.args[1]:
    #     logger.info( "Tested server does not support " + cipher[1])
