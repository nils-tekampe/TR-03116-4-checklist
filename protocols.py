#!/usr/local/bin/python
# -*- coding: utf-8 -*-

import socket, ssl
import subprocess
from tls_includes import cipher_suites
from helper import which, logger

protocols=[
[ssl.PROTOCOL_TLSv1, "TLSv1", False],
[ssl.PROTOCOL_TLSv1_1,"TLSv1.1", False],
[ssl.PROTOCOL_TLSv1_2,"TLSv1.2",True]]

def test_supported_protocols(hostname, port):

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


def test_supported_cipher_suites(hostname, port):
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


def test_session_renegotiation(hostname, port):
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

def test_tls_compression(hostname,port):
    logger.info("------------------------------------------------------------------------------------")
    logger.info("Anforderung 2.5.2 Überpruefe TLS Kompression")
    logger.info("------------------------------------------------------------------------------------")

    openssl_cmd_getcert=" echo "R" | openssl s_client -connect "+ hostname +":"+str(port)
    proc = subprocess.Popen([openssl_cmd_getcert], stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    (out, err) = proc.communicate()

    if "Compression: NONE" in out:
        logger.info("Server does not support compression. This is the expected behavior")
    else:
        logger.error("Server supports compression. This shold not be the case")


def test_heartbeat_extension(hostname,port):
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

def test_truncated_hmac_extension(hostname, port):
    logger.info("------------------------------------------------------------------------------------")
    logger.info("Anforderung 2.5.4 Überpruefe auf truncated_hmac-Extension")
    logger.info("------------------------------------------------------------------------------------")

    openssl_cmd_getcert=" echo Q | openssl s_client -connect "+ hostname +":"+str(port)+" -tlsextdebug"
    proc = subprocess.Popen([openssl_cmd_getcert], stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    (out, err) = proc.communicate()


    #TODO: wir brauchen mal einen Server mit einer truncated_hmac extension um zu sehen, ob das hier funktioniert.
    if "truncated_hmac" in out:
        logger.error("Server supports the truncated_hmac extension. This shold not be the case")
    else:
        logger.info("Server does not support the truncated_hmac extension. This is the intended behavior")
