#!/usr/local/bin/python

import socket, ssl
import logging, logging.config, os, pem
import subprocess
from cryptography import x509
from cryptography.hazmat.backends import default_backend


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
protocols=[[ssl.PROTOCOL_TLSv1, "TLSv1"],[ssl.PROTOCOL_TLSv1_1,"TLSv1.1"],[ssl.PROTOCOL_TLSv1_2,"TLSv1.2"]]

for protocol in protocols:
    try:
        context = ssl.SSLContext(protocol[0])
        context.verify_mode = ssl.CERT_REQUIRED
        context.check_hostname = True
        context.load_default_certs()

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ssl_sock = context.wrap_socket(s, server_hostname=hostname)

        ssl_sock.connect((hostname, 443))
        logger.info( "Tested server does support " + protocol[1])

    except ssl.SSLError as err:
        if "SSLV3_ALERT_HANDSHAKE_FAILURE" in err.args[1]:
            logger.info( "Tested server does not support " + protocol[1])

cipher_suites=[["TLS_RSA_WITH_NULL_SHA256","NULL-SHA256"],
 ["TLS_RSA_WITH_AES_128_CBC_SHA256","AES128-SHA256"],
 ["TLS_RSA_WITH_AES_256_CBC_SHA256","AES256-SHA256"],
 ["TLS_RSA_WITH_AES_128_GCM_SHA256","AES128-GCM-SHA256"],
 ["TLS_RSA_WITH_AES_256_GCM_SHA384","AES256-GCM-SHA384"],
 ["TLS_DH_RSA_WITH_AES_128_CBC_SHA256" ,"DH-RSA-AES128-SHA256"],
 ["TLS_DH_RSA_WITH_AES_256_CBC_SHA256","DH-RSA-AES256-SHA256"],
 ["TLS_DH_RSA_WITH_AES_128_GCM_SHA256","DH-RSA-AES128-GCM-SHA256"],
 ["TLS_DH_RSA_WITH_AES_256_GCM_SHA384","DH-RSA-AES256-GCM-SHA384"],
 ["TLS_DH_DSS_WITH_AES_128_CBC_SHA256","DH-DSS-AES128-SHA256"],
 ["TLS_DH_DSS_WITH_AES_256_CBC_SHA256", "DH-DSS-AES256-SHA256"],
 ["TLS_DH_DSS_WITH_AES_128_GCM_SHA256","DH-DSS-AES128-GCM-SHA256"],
 ["TLS_DH_DSS_WITH_AES_256_GCM_SHA384" ,"DH-DSS-AES256-GCM-SHA384"],
 ["TLS_DHE_RSA_WITH_AES_128_CBC_SHA256","DHE-RSA-AES128-SHA256"],
 ["TLS_DHE_RSA_WITH_AES_256_CBC_SHA256","DHE-RSA-AES256-SHA256"],
 ["TLS_DHE_RSA_WITH_AES_128_GCM_SHA256","DHE-RSA-AES128-GCM-SHA256"],
 ["TLS_DHE_RSA_WITH_AES_256_GCM_SHA384" ,"DHE-RSA-AES256-GCM-SHA384"],
 ["TLS_DHE_DSS_WITH_AES_128_CBC_SHA256","DHE-DSS-AES128-SHA256"],
 ["TLS_DHE_DSS_WITH_AES_256_CBC_SHA256" ,"DHE-DSS-AES256-SHA256"],
 ["TLS_DHE_DSS_WITH_AES_128_GCM_SHA256" ,"DHE-DSS-AES128-GCM-SHA256"],
 ["TLS_DHE_DSS_WITH_AES_256_GCM_SHA384","DHE-DSS-AES256-GCM-SHA384"],
 ["TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256","ECDH-RSA-AES128-SHA256"],
 ["TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384" ,"ECDH-RSA-AES256-SHA384"],
 ["TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256","ECDH-RSA-AES128-GCM-SHA256"],
 ["TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384" ,"ECDH-RSA-AES256-GCM-SHA384"],
 ["TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256" ,"ECDH-ECDSA-AES128-SHA256"],
 ["TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384" ,"ECDH-ECDSA-AES256-SHA384"],
 ["TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256","ECDH-ECDSA-AES128-GCM-SHA256"],
 ["TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384" , "ECDH-ECDSA-AES256-GCM-SHA384"],
 ["TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256","ECDHE-RSA-AES128-SHA256"],
 ["TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384","ECDHE-RSA-AES256-SHA384"],
 ["TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256","ECDHE-RSA-AES128-GCM-SHA256"],
 ["TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384","ECDHE-RSA-AES256-GCM-SHA384"],
 ["TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256","ECDHE-ECDSA-AES128-SHA256"],
 ["TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384","ECDHE-ECDSA-AES256-SHA384"],
 ["TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256" ,"ECDHE-ECDSA-AES128-GCM-SHA256"],
 ["TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384","ECDHE-ECDSA-AES256-GCM-SHA384"],
 ["TLS_DH_anon_WITH_AES_128_CBC_SHA256","ADH-AES128-SHA256"],
 ["TLS_DH_anon_WITH_AES_256_CBC_SHA256","ADH-AES256-SHA256"],
 ["TLS_DH_anon_WITH_AES_128_GCM_SHA256","ADH-AES128-GCM-SHA256"],
 ["TLS_DH_anon_WITH_AES_256_GCM_SHA384","ADH-AES256-GCM-SHA384"]]

# for cipher in cipher_suites:
#     try:
#         context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
#         context.set_ciphers(cipher[1])
#         context.verify_mode = ssl.CERT_REQUIRED
#         context.check_hostname = True
#         context.load_default_certs()
#
#         s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#         ssl_sock = context.wrap_socket(s, server_hostname=hostname)
#         ssl_sock.connect((hostname, 443))
#         logger.info( "Tested server does support " + cipher[0])
#
#     except ssl.SSLError as err:
#         if "SSLV3_ALERT_HANDSHAKE_FAILURE" in err.args[1]:
#             logger.info( "Tested server does not support " + cipher[1])
#

try:
    # cert=ssl.get_server_certificate((hostname,443))

    # pem=ssl.get_server_certificate((hostname,443))
    # print pem.encode('ascii','ignore')
    # cert = x509.load_pem_x509_certificate(pem.encode('ascii','ignore'), default_backend())
    #
    # print cert.serial_number
    # print cert.subject
    # print cert.issuer
    # print cert.signature_hash_algorithm
    # print cert.signature_algorithm_oid
    # print cert.public_key()
    # print cert.extensions#
    # print cert.get

    openssl_cmd_getcert="echo 'Q' | openssl s_client -connect www.google.de:443 -showcerts  | sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p'"

    proc = subprocess.Popen([openssl_cmd_getcert], stdout=subprocess.PIPE, shell=True)
    (out, err) = proc.communicate()


    certs = pem.parse(out)

    for cert in certs:
        print cert

    # process = subprocess.Popen([openssl_cmd_getcert], stdout=subprocess.PIPE, shell=True)
    # stdout = process.communicate()[0]
    # print 'STDOUT:{}'.format(stdout)
    #
    # while True:
    #     output = process.stdout.readline()
    #     if output == '' and process.poll() is not None:
    #         break
    #     if output:
    #         print output.strip()
    # rc = process.poll()

    #wenn das nicht funktioniert, dann geht immer nohc
# openssl s_client -connect www.google.de:443 -showcerts  | sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p'

    # print cert
    # print ssl.get_default_verify_paths()
    # context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    # context.set_ciphers(cipher[1])
    # context.verify_mode = ssl.CERT_REQUIRED
    # context.check_hostname = True
    # context.load_default_certs()
    #
    # s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # ssl_sock = context.wrap_socket(s, server_hostname=hostname)
    # ssl_sock.connect((hostname, 443))




except Exception as err:
    print err
    # if "SSLV3_ALERT_HANDSHAKE_FAILURE" in err.args[1]:
    #     logger.info( "Tested server does not support " + cipher[1])
