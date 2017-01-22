#!/usr/local/bin/python
# -*- coding: utf-8 -*-

import logging, logging.config, os, pem
import subprocess
from cryptography  import x509
from cryptography.hazmat.backends import default_backend
# from tls_includes import cipher_suites
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
import re
from cryptography.hazmat.primitives import serialization
from tls_includes import *

tmp_cert_file="/tmp/tmp.pem"

def check_intermediate_certificate(cert):
    logger.info("------------------------------------------------------------------------------------")
    logger.info("Diese Funktion überprüft ein Intermediate-Zertifikat und deckt die Anforderungen aus Kapitel 2.2 der Checkliste ab.")
    logger.info("------------------------------------------------------------------------------------")
    logger.info("Drucke das subject des Zertifikats. Dies dient nur der Übersicht")
    print_subject(cert)
    logger.info("------------------------------------------------------------------------------------")
    logger.info("Überprüfe den öffentlichen Schlüssel des Zertifkats (Anforderung 2.2.1)")
    check_certificate_key(cert)

    if is_cert_ca(cert):
        logger.info("------------------------------------------------------------------------------------")
        logger.info("Überprüfe den Signaturalgorithmus (Anforderung 2.2.2)")
        check_signature_algorithm(cert)

    if is_cert_ca(cert):
        logger.info("------------------------------------------------------------------------------------")
        logger.info("Überprüfe auf Wildcards (Anforderung 2.2.3)")
        check_for_wildcards(cert)

    if is_cert_ca(cert):
        logger.info("Überprüfe Rückrufinformationen und AuthorityInfoAccess (Anforderung 2.1.4)")
        check_cert_for_crl(cert)
        check_cert_for_aia(cert)


    if is_cert_ca(cert):
        logger.info("------------------------------------------------------------------------------------")
        logger.info("Überprüfe auf BasicConstraint Extension (Anforderung 2.2.5)")
        check_basic_constraint(cert)

    if is_cert_ca(cert):
        logger.info("------------------------------------------------------------------------------------")
        logger.info("Überprüfe keyUsageExtension (Anforderung 2.2.6)")
        check_cert_for_keyusage(cert)

def check_root_certificate(cert):
    logger.info("------------------------------------------------------------------------------------")
    logger.info("Diese Funktion überprüft das CA-Zertifikat und deckt die Anforderungen aus Kapitel 2.2 der Checkliste ab.")
    logger.info("------------------------------------------------------------------------------------")
    logger.info("Drucke das subject des Zertifikats. Dies dient nur der Übersicht")
    print_subject(cert)
    logger.info("------------------------------------------------------------------------------------")
    logger.info("Überprüfe den öffentlichen Schlüssel des Zertifkats (Anforderung 2.2.1)")
    check_certificate_key(cert)

    logger.info("------------------------------------------------------------------------------------")
    logger.info("Überprüfe auf Wildcards (Anforderung 2.2.3)")
    check_for_wildcards(cert)

    logger.info("------------------------------------------------------------------------------------")
    logger.info("Überprüfe auf BasicConstraint Extension (Anforderung 2.2.5)")
    check_basic_constraint(cert)

    logger.info("------------------------------------------------------------------------------------")
    logger.info("Überprüfe keyUsageExtension (Anforderung 2.2.6)")
    check_cert_for_keyusage(cert)


def check_leaf_certificate(cert):
    logger.info("------------------------------------------------------------------------------------")
    logger.info("Diese Funktion überprüft das Server-Zertifikat und deckt die Anforderungen aus Kapitel 2.1 der Checkliste ab.")
    logger.info("------------------------------------------------------------------------------------")
    logger.info("Drucke das subject des Zertifikats. Dies dient nur der Übersicht")
    print_subject(cert)
    logger.info("------------------------------------------------------------------------------------")
    logger.info("Überprüfe den öffentlichen Schlüssel des Zertifkats (Anforderung 2.1.1)")
    check_certificate_key(cert)
    logger.info("------------------------------------------------------------------------------------")
    logger.info("Überprüfe den Signaturalgorithmus (Anforderung 2.1.2)")
    check_signature_algorithm(cert)
    logger.info("------------------------------------------------------------------------------------")
    logger.info("Überprüfe auf Wildcards (Anforderung 2.1.3)")
    check_for_wildcards(cert)
    logger.info("------------------------------------------------------------------------------------")
    logger.info("Überprüfe Rückrufinformationen und AuthorityInfoAccess (Anforderung 2.1.4)")
    check_cert_for_crl(cert)
    check_cert_for_aia(cert)
    logger.info("------------------------------------------------------------------------------------")
    logger.info("Überprüfe ob das Zertifikat gesperrt ist (Anforderung 2.1.5)")
    check_cert_for_revocation(cert)
    logger.info("------------------------------------------------------------------------------------")
    logger.info("Überprüfe keyUsageExtension (Anforderung 2.1.6)")
    check_cert_for_keyusage(cert)
    logger.info("------------------------------------------------------------------------------------")
    logger.info("Überprüfe extendedKeyUsageExtension (Anforderung 2.1.7)")
    check_cert_for_extended_keyusage(cert)
    logger.info("------------------------------------------------------------------------------------")
    logger.info("Überprüfe Sub-Domain Namen (Anforderung 2.1.7)")
    list_alternative_names(cert)



def read_certificates(hostname,port):
    logger.info("------------------------------------------------------------------------------------")
    logger.info("Rufe die Zertifkate für die weiteren Tests ab")
    logger.info("------------------------------------------------------------------------------------")
    try:
        openssl_cmd_getcert="echo 'Q' | openssl s_client -connect "+ hostname +":"+str(port)+ " -showcerts  | sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p'"
        proc = subprocess.Popen([openssl_cmd_getcert], stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        (out, err) = proc.communicate()

        certs = pem.parse(out)
        logger.info(str(len(certs)) +" Zertifikate wurden empfangen.")

        x509_certs = [load_pem_x509_certificate(str(x).encode('ascii','ignore'),default_backend()) for x in certs]

        return x509_certs


    except Exception as err:
        print err


def check_certificate_key(cert):
    if (type(cert.public_key()) is _RSAPublicKey):
        logger.info("This certificate has an RSA key")
        if cert.public_key().key_size >= 2048:
            logger.info("Die Groesse des Schluessels ist gleich oder groesser 2048. Das ist OK.")
        else:
            logger.error("Die Groesse des Schluessels ist kleiner 2048bit. Das sollte nicht der Fall sein.")

        # logger.info.("The key size is: "+str(cert.public_key().key_size))
    if (type(cert.public_key())==DSAPublicKey):
        logger.error("Das Zertifikat hat einen DSA key. Das sollte nicht der Fall sein. Das Skript wird hier beendet da die weiteren Tests nicht sinnvoll sind.")
        exit(1)
        #TODO: Der Fall muss noch getestet werden. Die genaue Bezeichnung des Types des public_key ist vermutlich anders
    if (type(cert.public_key())==EllipticCurvePublicKey):
        logger.info("Das Zertifikat hat einen EllipticCurvePublicKey")
        logger.warning("Es wird folgende Kurfe verwendet:"+ str(cert.public_key().curve.name)+ " Bitte mit der Checkliste abgleichen")
        #TODO: Checken, dass der name der Kurve denen in der Checkliste entspricht
        #TODO: Der Fall muss noch getestet werden. Die genaue Bezeichnung des Types des public_key ist vermutlich anders

def check_signature_algorithm(cert):
    logger.warning("Der verwendete Signaturalgorithmus ist : "+str(cert.signature_algorithm_oid._name))
    logger.warning("Die zugehörige OID lautet: "+str(cert.signature_algorithm_oid.dotted_string))
    logger.warning("Bitte mit Hilfe der Checkliste überprüfen")


def check_for_wildcards(cert):
    #TODO: Das ist in CA Zertifkaten anders. Und es müssen auch noch mehr Felder geprüft werden.
    for entry in cert.subject._attributes:
        for attr in entry:
            if attr.oid._name=="commonName":
                logger.info("commonName im subject des Zertifikat hat den Wert: " + attr.value)
    try:
        name_extension=cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        logger.info("Das Zertifikat hat eine AlternativeName Extension")
    #    logger.info("Der Inhalt der AlternativeName Extension lautet: "+str(name_extension))


        if re.search(r"\*+",str(name_extension))==None:
            logger.error("Die AlternativeName-Extension enthält mindestens ein *. Das ist nicht OK")
        else:
            logger.error("Die AlternativeName-Extension enthält keine Wildcards. Das ist  OK")

    except Exception as err:
        logger.error("Es existiert keine AlternativeName-Extension")
        #TODO: wenn es die Extension nicht gibt, tritt vermutlich ein Fehler auf, den man hier behandeln sollte


def check_cert_for_crl(cert):
    try:
        crl_extension=cert.extensions.get_extension_for_class(x509.CRLDistributionPoints)
        logger.info("Das Zertifikat hat eine CRLDistributionPoint Extension")
        logger.info("Der Inhalt der CRLDistributionPoint Extension lautet:")
        logger.info(str(crl_extension))
        #TODO: Die Ausgabe der Extension könnte etwas schöner werden

    except Exception as err:
        print err
        #TODO: wenn es die Extension nicht gibt, tritt vermutlich ein Fehler auf, den man hier behandeln sollte

def check_cert_for_aia(cert):
    try:
        aia_extension=cert.extensions.get_extension_for_class(x509.AuthorityInformationAccess)
        logger.info("Das Zertifikat hat eine AuthorityInformationAccess Extension")
        logger.info("Der Inhalt der AuthorityInformationAccess Extension lautet:")
        logger.info(str(aia_extension))
        #TODO: Die Ausgabe der Extension könnte etwas schöner werden

    except Exception as err:
        print err
        #TODO: wenn es die Extension nicht gibt, tritt vermutlich ein Fehler auf, den man hier behandeln sollte

def check_cert_for_revocation(cert):

    with open(tmp_cert_file, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    try:
        crl_extension=cert.extensions.get_extension_for_class(x509.CRLDistributionPoints)
        logger.info("Das Zertifikat hat eine CRLDistributionPoint Extension")

        openssl_cmd_getcert="openssl verify -crl_check_all -CAfile "+ca_file+ " " + tmp_cert_file
        proc = subprocess.Popen([openssl_cmd_getcert], stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        (out, err) = proc.communicate()

        logger.warning("Die Prüfung des Zertifikats gegen die CRL hat folgendes Ergebnis ergeben:")
        logger.warning(out)
        logger.warning(err)


#TODO: CRL auswerten

    except Exception as err:
        print err
        #TODO: wenn es die Extension nicht gibt, tritt vermutlich ein Fehler auf, den man hier behandeln sollte

def check_cert_for_keyusage(cert):
    try:
        keyusage_extension=cert.extensions.get_extension_for_class(x509.KeyUsage)
        logger.info("Das Zertifikat hat eine KeyUsage Extension mit den folgenden Eigenschaften")
        logger.warning("digital_signature: "+ str(keyusage_extension.value.digital_signature))
        logger.warning("key_cert_sign: "+ str(keyusage_extension.value.key_cert_sign))
        logger.warning("crl_sign: "+ str(keyusage_extension.value.crl_sign))

        #TODO: Man könnte die Werte auch gleich prüfen, allerdings ist das für CA Zertifkate anders .

    except Exception as err:
        print err
        #TODO: wenn es die Extension nicht gibt, tritt vermutlich ein Fehler auf, den man hier behandeln sollte

def check_cert_for_extended_keyusage(cert):
    try:
        keyusage_extension=cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
        # logger.info("Das Zertifikat hat eine ExtendedKeyUsage Extension mit den folgenden Eigenschaften")
        # logger.warning("serverAuth: "+ str(keyusage_extension.value.SERVER_AUTH))

        for usg in keyusage_extension.value._usages:
            logger.warning("Das Zertifikat hat eine ExtendedKeyUsage Extension mit den folgenden Eigenschaften"+usg._name)


        #TODO: Ist das der richtige Wert?
    except Exception as err:
        print err
        #TODO: wenn es die Extension nicht gibt, tritt vermutlich ein Fehler auf, den man hier behandeln sollte

def list_alternative_names(cert):

    try:
        name_extension=cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        logger.info("Das Zertifikat hat eine AlternateiveName Extension")
        logger.info("Die Einträge für AlternativeNames lauten: ")

        for entry in name_extension._value._general_names:
            logger.info(entry._value)


    except Exception as err:
        print err
        #TODO: wenn es die Extension nicht gibt, tritt vermutlich ein Fehler auf, den man hier behandeln sollte

def check_basic_constraint(cert):
#Anforderung 2.2.5
    try:
        basic_constraint_extension=cert.extensions.get_extension_for_class(x509.BasicConstraints)
        logger.info("Das Zertifikat hat eine BasicContraint Extension")
        logger.warning("Der Inhalt der BasicContraint Extension ist: "+str(basic_constraint_extension))

        #TODO: Die Extension könnte man noch nett auswerten.

    except Exception as err:
        logger.error("Das Zertifikat hat keine BasicContraint Extension")


def is_cert_ca(cert):
    try:
        basic_constraint_extension=cert.extensions.get_extension_for_class(x509.BasicConstraints)
        return True

    except Exception as err:
        return False


def print_subject(cert):
    for entry in cert.subject._attributes:
        for attr in entry:
            logger.info( attr.oid._name+ ": " + attr.value)

def print_serial(cert):
        print cert.serial_number
        print cert.subject
        print cert.issuer
        print cert.signature_hash_algorithm
        print cert.signature_algorithm_oid
        print cert.public_key()
        print cert.extensions
