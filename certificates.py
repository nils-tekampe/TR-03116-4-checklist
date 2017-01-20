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


def read_certificates(hostname,port):
    # --------------
    logger.info("------------------------------------------------------------------------------------")
    logger.info("We will now obtain the certificates for the later test cases")
    logger.info("------------------------------------------------------------------------------------")
    try:

        openssl_cmd_getcert="echo 'Q' | openssl s_client -connect "+ hostname +":"+str(port)+ " -showcerts  | sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p'"
        proc = subprocess.Popen([openssl_cmd_getcert], stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        (out, err) = proc.communicate()

        certs = pem.parse(out)

        logger.info(str(len(certs)) +" Certificates have been obtained.")

        return certs

    except Exception as err:
        print err



        for entry in certs:
            cert = x509.load_pem_x509_certificate(str(entry).encode('ascii','ignore'), default_backend())
            logger.info("Now checking certificate with serial: "+str(cert.serial_number))
            logger.info("Here come the attributes of the subject of the certificate:")
            for attribute in cert.subject:
                logger.info(attribute)

            logger.info("The signature algorithm of the certificate is: "+str(cert.signature_algorithm_oid))

            # if (type(cert.public_key())==cryptography.hazmat.backends.openssl.rsa._RSAPublicKey):
            #     logger.info("This certificate has an RSA key")
                # logger.info.("The key size is: "+str(cert.public_key().key_size)
            # if (type(cert.public_key())==cryptography.hazmat.primitives.asymmetric.dsa.DSAPublicKey):
            #     logger.error("This certificate has an DSA key. This should not be the case")
            # if (type(cert.public_key())==cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicKey):
            #     logger.info("This certificate has an EllipticCurvePublicKey key")


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

            # extendedKeyUsage=cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
            # logger.warning("The extendedKeyUsage extension contains:")
            # logger.warning(extendedKeyUsage)

            # print cert.serial_number
            # print cert.subject
            # print cert.issuer
            # print cert.signature_hash_algorithm
            # print cert.signature_algorithm_oid
            # print cert.public_key()
            # print cert.extensions
