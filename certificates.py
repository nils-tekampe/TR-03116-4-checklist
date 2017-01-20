#!/usr/local/bin/python
# -*- coding: utf-8 -*-

import socket, ssl
import logging, logging.config, os, pem
import subprocess
from cryptography  import x509
from cryptography.hazmat.backends import default_backend
from tls_includes import cipher_suites
import colorlog
from helper import which, logger
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.asymmetric.dsa import DSAPublicKey
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.hazmat.backends.openssl.rsa import _RSAPublicKey
from cryptography.x509 import Certificate
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurve
import cryptography.x509
from cryptography.x509.oid import ExtensionOID



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

        x509_certs = [load_pem_x509_certificate(str(x).encode('ascii','ignore'),default_backend()) for x in certs]

        return x509_certs


    except Exception as err:
        print err


def check_certificate_key(cert):
    if (type(cert.public_key()) is _RSAPublicKey):
        logger.info("This certificate has an RSA key")
        if cert.public_key().key_size >= 2048:
            logger.info("The key size is equal to or greater than 2048.")
        else:
            logger.error("The key size is smaller than 2048. This should not be the case")

        # logger.info.("The key size is: "+str(cert.public_key().key_size))
    if (type(cert.public_key())==DSAPublicKey):
        logger.error("This certificate has an DSA key. This should not be the case")
        #TODO: Der Fall muss noch getestet werden. Die genaue Bezeichnung des Types des public_key ist vermutlich anders
    if (type(cert.public_key())==EllipticCurvePublicKey):
        logger.info("This certificate has an EllipticCurvePublicKey key")
        print cert.public_key().curve.name
        #TODO: Checken, dass der name der Kurve denen in der Checkliste entspricht
        #TODO: Der Fall muss noch getestet werden. Die genaue Bezeichnung des Types des public_key ist vermutlich anders

def check_signature_algorithm(cert):
    logger.warning("The signature algorithm of the certificate is: "+str(cert.signature_algorithm_oid._name))
    logger.warning("The corresponding OID is: "+str(cert.signature_algorithm_oid.dotted_string))
    logger.warning("Please check with the checklist")


def check_for_wildcards(cert):
    print cert.subject._attributes

    print type(cert.subject._attributes[1])

    #TODO: Muss noch fertiggestellt werden
    #TODO: auch die Extension fpr Alternative Names checken


def check_cert_for_crl(cert):
    try:
        crl_extension=cert.extensions.get_extension_for_class(x509.CRLDistributionPoints)
        logger.info("The certificate has a CRLDistributionPoint Extension")

    except Exception as err:
        print err
        #TODO: wenn es die Extension nicht gibt, tritt vermutlich ein Fehler auf, den man hier behandeln sollte

def check_cert_for_aia(cert):
    try:
        crl_extension=cert.extensions.get_extension_for_class(x509.AuthorityInformationAccess)
        logger.info("The certificate has a AuthorityInformationAccess Extension")

    except Exception as err:
        print err
        #TODO: wenn es die Extension nicht gibt, tritt vermutlich ein Fehler auf, den man hier behandeln sollte

def check_cert_for_revocation(cert):
    try:
        crl_extension=cert.extensions.get_extension_for_class(x509.CRLDistributionPoints)
        logger.info("The certificate has a CRLDistributionPoint Extension")
#TODO: CRL auswerten

    except Exception as err:
        print err
        #TODO: wenn es die Extension nicht gibt, tritt vermutlich ein Fehler auf, den man hier behandeln sollte

def check_cert_for_keyusage(cert):
    try:
        keyusage_extension=cert.extensions.get_extension_for_class(x509.KeyUsage)
        logger.info("The certificate has a KeyUsage Extension with the following settings")
        logger.warning("digital_signature: "+ str(keyusage_extension.value.digital_signature))
        logger.warning("key_cert_sign: "+ str(keyusage_extension.value.key_cert_sign))
        logger.warning("crl_sign: "+ str(keyusage_extension.value.crl_sign))

        #TODO: Man könnte die Werte auch gleich prüfen.

    except Exception as err:
        print err
        #TODO: wenn es die Extension nicht gibt, tritt vermutlich ein Fehler auf, den man hier behandeln sollte

def check_cert_for_extended_keyusage(cert):
    try:
        keyusage_extension=cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
        logger.info("The certificate has a ExtendedKeyUsage Extension with the following settings")
        # logger.warning("serverAuth: "+ str(keyusage_extension.value.SERVER_AUTH))

        print dict(keyusage_extension)


        #TODO: Ist das der richtige Wert?
    except Exception as err:
        print err
        #TODO: wenn es die Extension nicht gibt, tritt vermutlich ein Fehler auf, den man hier behandeln sollte


        # for entry in certs:
        #     cert = x509.load_pem_x509_certificate(str(entry).encode('ascii','ignore'), default_backend())
        #     logger.info("Now checking certificate with serial: "+str(cert.serial_number))
        #     logger.info("Here come the attributes of the subject of the certificate:")
        #     for attribute in cert.subject:
        #         logger.info(attribute)
        #
        #
        #
        #     logger.info("The certificate contains the following extensions:")
        #     for extension in cert.extensions:
        #         logger.info(extension.oid)
        #
        #     keyUsage=cert.extensions.get_extension_for_class(x509.KeyUsage)
        #     # print keyUsage
        #     # print type(keyUsage)
        #     logger.warning("The keyUsage extension contains:")
        #     logger.warning("digital_signature:"+str(keyUsage.value.digital_signature))
        #     logger.warning("key_cert_sign:"+str(keyUsage.value.key_cert_sign))
        #     logger.warning("crl_sign:"+str(keyUsage.value.crl_sign))
        #
        #     # extendedKeyUsage=cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
        #     # logger.warning("The extendedKeyUsage extension contains:")
        #     # logger.warning(extendedKeyUsage)
        #
        #     # print cert.serial_number
        #     # print cert.subject
        #     # print cert.issuer
        #     # print cert.signature_hash_algorithm
        #     # print cert.signature_algorithm_oid
        #     # print cert.public_key()
        #     # print cert.extensions
