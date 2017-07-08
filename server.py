#!/usr/bin/python
# -*- coding: utf-8 -*-

import string
import socket, ssl, pem
import sys
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.backends import default_backend
import subprocess
from helper import which, logger, print_h1, print_h2
from certificate import Certificate

class Server:

    x509_certs=[]
    certs=[]
    number_of_certs=0
    cipher_suites=[
      ["TLS_DHE_RSA_WITH_AES_128_CBC_SHA256","DHE-RSA-AES128-SHA256","RSA","OPTIONAL"  ],
      ["TLS_DHE_RSA_WITH_AES_256_CBC_SHA256","DHE-RSA-AES256-SHA256", "RSA", "OPTIONAL" ],
      ["TLS_DHE_RSA_WITH_AES_128_GCM_SHA256","DHE-RSA-AES128-GCM-SHA256","RSA", "OPTIONAL"  ],
      ["TLS_DHE_RSA_WITH_AES_256_GCM_SHA384" ,"DHE-RSA-AES256-GCM-SHA384","RSA", "OPTIONAL"  ],
      ["TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256","ECDHE-RSA-AES128-SHA256","RSA","MUST"  ],
      ["TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384","ECDHE-RSA-AES256-SHA384","RSA", "SHOULD"  ],
      ["TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256","ECDHE-RSA-AES128-GCM-SHA256","RSA","MUST"  ],
      ["TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384","ECDHE-RSA-AES256-GCM-SHA384","RSA","SHOULD"  ],
      ["TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA","ECDHE-RSA-AES128-SHA","RSA","OPTIONAL"],
      ["TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA","","RSA","OPTIONAL"], #TODO: Mein Openssl unterstützt diese Cipher gar nicht.
      ["TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA","ECDHE-RSA-AES256-SHA","RSA","OPTIONAL"],
      ["TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA","","RSA","OPTIONAL"],#TODO: Mein Openssl unterstützt diese Cipher gar nicht.
      ["TLS_DHE_RSA_WITH_AES_128_CBC_SHA","DHE-RSA-AES128-SHA","RSA","OPTIONAL"],
      ["TLS_DHE_RSA_WITH_AES_256_CBC_SHA","DHE-RSA-AES256-SHA","RSA","OPTIONAL"],
      ["TLS_DHE_RSA_WITH_AES_128_GCM_SHA","","RSA","OPTIONAL"],#TODO: Mein Openssl unterstützt diese Cipher gar nicht.
      ["TLS_DHE_RSA_WITH_AES_256_GCM_SHA","","RSA","OPTIONAL"],#TODO: Mein Openssl unterstützt diese Cipher gar nicht.
      ["TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256","ECDHE-ECDSA-AES128-SHA256", "EC", "MUST"],
      ["TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384","ECDHE-ECDSA-AES256-SHA384","EC", "SHOULD"  ],
      ["TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256" ,"ECDHE-ECDSA-AES128-GCM-SHA256","EC", "MUST"  ],
      ["TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384","ECDHE-ECDSA-AES256-GCM-SHA384","EC", "SHOULD"  ],
      ["TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA","ECDHE-ECDSA-AES128-SHA","EC", "OPTIONAL"  ],
      ["TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA","ECDHE-ECDSA-AES256-SHA","EC", "OPTIONAL"  ],
      ["TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA","","EC", "OPTIONAL"  ],#TODO: Mein Openssl unterstützt diese Cipher gar nicht.
      ["TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA","","EC", "OPTIONAL"  ]#TODO: Mein Openssl unterstützt diese Cipher gar nicht.
    ]

    # short names for ecc curves
    # https://tools.ietf.org/html/rfc4492#section-5.1.1
    # https://2rfc.net/7027#2
    ec_curve_names={
      21:'secp224r1',
      23:'secp256r1',
      24:'secp384r1',
      25:'secp521r1',
      26:'brainpoolP256r1',
      27:'brainpoolP384r1',
      28:'brainpoolP512r1',
    }

    def __init__(self, hostname, port, ca_file, clientcert_file, certificates, proxy, insecure):
      self.hostname = hostname
      self.port=port
      self.proxy=proxy
      self.ca_file=ca_file
      self.clientcert_file=clientcert_file
      self.certificates= certificates
      # do not verify certificate validity and cn
      self.insecure=insecure
      self.protocols=[
      [ssl.PROTOCOL_TLSv1, "TLSv1", False],
      [ssl.PROTOCOL_TLSv1_1,"TLSv1.1", False],
      [ssl.PROTOCOL_TLSv1_2,"TLSv1.2",True]]
      self.openssl_client_proxy_part = ""
      self.sslyze_proxy_part = ""
      if self.proxy is not None:
        self.openssl_client_proxy_part = " -proxy " + self.proxy[0] + ":" + str(self.proxy[1]) + " "
        self.sslyze_proxy_part = " --https_tunnel=http:\\" + self.proxy[0] + ":" + str(self.proxy[1]) + " "  

    def test_server_for_protocol(self):
        print_h1("Test die Anforderungen aus Kapitel 2.3")
        print_h2("Anforderung 2.3.1 Überpruefe die unterstuetzten Protokolle:")
        self.test_supported_protocols()

        print_h2("Anforderung 2.3.2/2.3.3/2.3.4 Überpruefe die unterstuetzten Cipher-Suites:")
        logger.info("Im Folgenden werden die vom Server unterstützten Cipher-Suites gelistet.")
        logger.info("Unerlaubte Cipher-Suites werden direkt markiert. Allerdings muss aktuelle manuell geprpft werden ")
        logger.info("ob die verpflichtenden cipher-suites umgesetzt sind. Außerdem muss die Priorität der  ")
        logger.info("Cipher Suites aktuell manuell geprüft werden.")

        self.test_supported_cipher_suites()

        print_h1("Teste die Anforderungen aus Kapitel 2.4")
        print_h2("Anforderung 2.4.1 Überprüfe die ephemeralen Parameter")
        self.test_key_exchange()

        print_h1("Teste die Anforderungen aus Kapitel 2.5")
        print_h2("Anforderung 2.5.1 Überpruefe Session Renegotiation")
        self.test_session_renegotiation()

        print_h2("Anforderung 2.5.2 Überpruefe TLS Kompression")
        self.test_tls_compression()

        print_h2("Anforderung 2.5.3 Überpruefe auf Heartbeat-Extension")
        self.test_heartbeat_extension()

        print_h2("Anforderung 2.5.4 Überpruefe auf truncated_hmac-Extension")
        self.test_truncated_hmac_extension()

    def test_supported_protocols(self):
        #Kritierum 2.3.1
        for protocol in self.protocols:

            context = ssl.SSLContext(protocol[0])
            if self.insecure:
                context.verify_mode = ssl.CERT_NONE
                context.check_hostname = False
            else:
                context.verify_mode = ssl.CERT_REQUIRED
                context.check_hostname = True

            if self.ca_file:
                context.load_verify_locations(cafile=self.ca_file)
            else:
                context.load_default_certs()

            if self.clientcert_file:
                context.load_cert_chain(certfile=self.clientcert_file)

            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                ssl_sock = context.wrap_socket(s, server_hostname=self.hostname)
                ssl_sock.connect((self.hostname, self.port))

                if protocol[2]:
                    logger.info("Server unterstützt " + protocol[1] + " Dieses Verhalten ist OK")
                else:
                    logger.error("Server unterstützt " + protocol[1] + " Das sollte nicht der Fall sein")

            except ssl.SSLError as err:
                if "SSLV3_ALERT_HANDSHAKE_FAILURE" in err.args[1] or "EOF occurred in violation of protocol" in err.args[1]:
                    if not protocol[2]:
                        logger.info("Server unterstützt NICHT " + protocol[1] + " Dieses Verhalten ist OK")
                    else:
                        logger.error("Server unterstützt NICHT " + protocol[1] + " Das sollte nicht der Fall sein")
                else:
                    logger.error("unbekannter Fehler bei Test von " + protocol[1])
                    print(err)

            except Exception as err:
                logger.error("unbekannter Fehler bei Test von " + protocol[1])
                print(err)

    def test_supported_cipher_suites(self):
    #Anforderung 2.3.2/2.3.3/2.3.4
    #TODO: Funktioniert aktuell nur mit RSA
        crypto_type="RSA"
        openssl_cmd_getcert="openssl ciphers"
        proc = subprocess.Popen([openssl_cmd_getcert], stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        (out, err) = proc.communicate()

        out = out.replace('\n', '').replace('\r', '')
        all_ciphers=out.split(":")
        all_ciphers = filter(None, all_ciphers)
        all_ciphers = filter(None, all_ciphers)

        for cipher in all_ciphers:
            cipher_list = [x for x in self.cipher_suites if x[1] == cipher and x[2]==crypto_type ]
            allowed=should=must=optional=False

            if len(cipher_list)==0:
                allowed=False
            elif cipher_list[0][3]=="MUST":
                must=True
                allowed=True
            elif cipher_list[0][3]=="SHOULD":
                should=True
                allowed=True
            elif cipher_list[0][3]=="OPTIONAL":
                optional=True
                allowed=True

            context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
            context.set_ciphers(cipher)
            if self.insecure:
                context.verify_mode = ssl.CERT_NONE
                context.check_hostname = False
            else:
                context.verify_mode = ssl.CERT_REQUIRED
                context.check_hostname = True

            if self.ca_file:
                context.load_verify_locations(cafile=self.ca_file)
            else:
                context.load_default_certs()
            if self.clientcert_file:
                context.load_cert_chain(certfile=self.clientcert_file)

            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                ssl_sock = context.wrap_socket(s, server_hostname=self.hostname)
                ssl_sock.connect((self.hostname, self.port))
                priority= ssl_sock.cipher()[2]

                if not allowed:
                    logger.error("Server unterstützt verbotene cipher-suite: " + cipher + " mit Priorität" + str(priority) +  " Das sollte nicht der Fall sein")

                elif must or should or optional:
                    logger.warning(cipher + " wird unterstützt mit Priorität" + str(priority) + ". Bitte in der Checkliste prüfen.")


            # Zertifikatfehler
            except ssl.CertificateError as err:
                logger.error("Zertifikatfehler bei Überprüfung von %s" % (cipher) )
                print(err)

            # ssl Verbindungsabbruch
            except ssl.SSLError as err:
                if len(err.args) > 1:
                    if "SSLV3_ALERT_HANDSHAKE_FAILURE" in err.args[1] or "NO_CIPHERS_AVAILABLE" in err.args[1] or "EOF occurred in violation of protocol" in err.args[1]:
                        if must:
                            logger.error(cipher + " wird nicht unterstützt aber von der Checkliste gefordert")
                        else:
                            logger.info(cipher + " wird nicht unterstützt. Das scheint OK zu sein.")
                    # DH Key zu klein
                    elif "dh key too small" in err.args[1]:
                        logger.warn(cipher + " " + err.args[1])
                    # sonstiger Grund
                    else:
                        logger.warn(cipher + " verursacht einen Verbindungsfehler")
                        print(err.args[1])
                if len(err.args) == 1:
                    if must:
                        logger.error(cipher + " wird nicht unterstützt aber von der Checkliste gefordert")
                    else:
                        logger.info(cipher + " wird nicht unterstützt. Das scheint OK zu sein.")

            # socket Fehler
            except socket.error as err:
                if must:
                    logger.error(cipher + " wird nicht unterstützt aber von der Checkliste gefordert")
                else:
                    logger.info(cipher + " wird nicht unterstützt. Das scheint OK zu sein.")

    def test_key_exchange(self):
        #Anforderung 2.4.1

        # key exchange dh Länge anzeigen
        openssl_cmd_getcert="echo | openssl s_client -msg -connect "+ self.hostname +":"+ str(self.port)+ self.openssl_client_proxy_part + " | grep 'Server Temp Key:'"
        
        proc = subprocess.Popen([openssl_cmd_getcert], stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        (out, err) = proc.communicate()

        out_list=out.splitlines()
        if len(out_list)<1:
            logger.warn("Parameter konnten nicht gelesen werden")
            logger.warn(out)
            return
             
        if "Server Temp Key: DH," in out_list[0]:
            bits=int(out_list[0].split()[-2])
            if bits <2048:
                logger.error("Verwendete Keylänge ist kleiner als 2048 bit. Das ist nicht OK")
                logger.warn(out)
            else:
                logger.info("Verwendete Keylänge beträgt mind. 2048 bit. Das ist so OK.")
                logger.info(out)
            return

        elif "Server Temp Key: ECDH" in out_list[0]:

            # verwendete ecc Kurve anzeigen
            # http://crypto.stackexchange.com/questions/11310/with-openssl-and-ecdhe-how-to-show-the-actual-curve-being-used
            # openssl key exchange short description

            openssl_cmd_getcert="echo | openssl s_client -msg -connect "+ self.hostname +":"+ str(self.port)+ self.openssl_client_proxy_part +" | grep 'ServerKey' -A 5"

            proc = subprocess.Popen([openssl_cmd_getcert], stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
            (out, err) = proc.communicate()

            out_list=out.splitlines()
            if len(out_list)<2:
                logger.warn("Parameter konnten nicht gelesen werden")
                logger.warn(out)
                return
            
            param_list=out_list[1].strip().split()
            if param_list[0]!="0c" or param_list[4]!="03":
                logger.warn("Parameter passen nicht zu ECDH Werten")
                logger.warn(out)
                return
            
            decimal_curve_id=int(param_list[5]+param_list[6],16)
            if decimal_curve_id in self.ec_curve_names:
                logger.info("Verwendete ECDHE Kurve: "+ self.ec_curve_names[decimal_curve_id]+". Das ist so OK.")
            else:
                logger.warn("Verwendete ECDHE Kurve unbekannt, bitte manuell prüfen")
                logger.warn(out)

        else:          
            logger.warn("Verwendeter Key Exchange unbekannt, bitte manuell überprüfen")
            logger.warn(out)
            return


    def test_session_renegotiation(self):
    #Anforderung 2.5.1

        if self.ca_file:
            sslyze_ca_opt="--ca_file="+ self.ca_file
        else:
            sslyze_ca_opt=""
        if self.clientcert_file:
            sslyze_clientcert_opt="--cert="+ self.clientcert_file + " --key="+ self.clientcert_file
        else:
            sslyze_clientcert_opt=""

        openssl_cmd_getcert="sslyze --reneg " + sslyze_ca_opt +" "+ sslyze_clientcert_opt +" "+ self.hostname +":"+str(self.port) + self.sslyze_proxy_part
        proc = subprocess.Popen([openssl_cmd_getcert], stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        (out, err) = proc.communicate()

        if "ClientCertificateRequested" in out:
            logger.warning("sslyze Fehler: ClientCertificateRequested")
            return

        if "Unhandled exception" in out:
            logger.warning("unbekannter Fehler bei Ausführung von sslyze")
            print(out)
            return

# Anmerkung: die sslyze-ausgabe client-initiated renegotiation: ok-rejected ist ein rein positives security-merkmal und dürfte nicht als regel-verstoß gewertet werden.
# bitte prüfen
        if "Client-initiated Renegotiation" in out:
            if "Client-initiated Renegotiation:    OK - Rejected" in out:
                logger.info("Server unterstützt client-initiierte session renegotiation nicht. Das ist so OK")
                logger.warning(" - in der upstream-version dieses prüftools wird dieser prüfpunkt als fehler gewertet. ggfs. diesen punkt klären.")
            else:
                logger.error("Server unterstützt client-initiierte session renegotiation. Das sollte nicht der Fall sein.")
        else:
            logger.warning("kein Ergebnis für Client-initiated Renegotiation")

# Anmerkung: die secure renegotiation ist eine rein positives security-merkmal und dürfte nicht als regel-verstoß gewertet werden.
# bitte prüfen
        if "Secure Renegotiation:" in out:
            if "Secure Renegotiation:              OK - Supported" in out:
                logger.info("Der Server unterstützt die sichere Form der renegotiaion. Das ist so OK.")
                logger.warning(" - in der upstream-version dieses prüftools wird dieser prüfpunkt als fehler gewertet. ggfs. diesen punkt klären.")
            else:
                logger.warning("Der Server unterstützt die sichere Form der renegotiation nicht. Bitte im Detail prüfen.")
        else:
            logger.warning("kein Ergebnis für Secure Renegotiation")


    def test_tls_compression(self):
    #Anforderung 2.5.2

        if self.ca_file:
            openssl_ca_opt="-CAfile "+ self.ca_file
        else:
            openssl_ca_opt=""
        openssl_cmd_getcert=" echo "R" | openssl s_client " + openssl_ca_opt + " -connect "+ self.hostname +":"+str(self.port) + self.openssl_client_proxy_part
        
        proc = subprocess.Popen([openssl_cmd_getcert], stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        (out, err) = proc.communicate()

        if "Compression: NONE" in out:
            logger.info("Server unterstützt keine TLS compression. Das ist das erwartete Verhalten.")
        else:
            logger.error("Server unterstützt TLS compression. Das sollte nicht der Fall sein.")


    def test_heartbeat_extension(self):
        #Anforderung 2.5.3
        #Thanks to  https://www.feistyduck.com/library/openssl-cookbook/online/ch-testing-with-openssl.html

        if self.ca_file:
            openssl_ca_opt="-CAfile "+ self.ca_file
        else:
            openssl_ca_opt=""
        openssl_cmd_getcert=" echo Q | openssl s_client " + openssl_ca_opt + " -connect "+ self.hostname +":"+str(self.port)+" -tlsextdebug"+self.openssl_client_proxy_part

        proc = subprocess.Popen([openssl_cmd_getcert], stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        (out, err) = proc.communicate()

        if "heartbeat" in out:
            logger.error("Server unterstützt die Heartbeat-extension. Das sollte nicht der Fall sein.")
        else:
            logger.info("Server unterstützt die Heartbeat-Extension nicht. Das ist so OK.")

    def test_truncated_hmac_extension(self):
    #Anforderung 2.5.4
        if self.ca_file:
            openssl_ca_opt="-CAfile "+ self.ca_file
        else:
            openssl_ca_opt=""
        openssl_cmd_getcert=" echo Q | openssl s_client " + openssl_ca_opt +" -connect "+ self.hostname +":"+str(self.port)+" -tlsextdebug" + self.openssl_client_proxy_part
        proc = subprocess.Popen([openssl_cmd_getcert], stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        (out, err) = proc.communicate()


        #TODO: wir brauchen mal einen Server mit einer truncated_hmac extension um zu sehen, ob das hier funktioniert.
        if "truncated_hmac" in out:
            logger.error("Server unterstützt die truncated_hmac extension. Das sollte nicht der Fall sein.")
        else:
            logger.info("Server unterstützt die truncated_hmac extension nicht. Das ist OK.")

    def read_certificates(self,server_certificates):
        logger.info("------------------------------------------------------------------------------------")
        logger.info("Rufe die Zertifkate für die weiteren Tests ab")
        logger.info("------------------------------------------------------------------------------------")
        try:
            if server_certificates is None:
                
                openssl_cmd_getcert="echo 'Q' | openssl s_client -connect "+ self.hostname +":"+str(self.port)+ self.openssl_client_proxy_part + " -showcerts  | sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p'"
                proc = subprocess.Popen([openssl_cmd_getcert], stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
                (out, err) = proc.communicate()
                tmp_certs = pem.parse(out)
            else:
                tmp_certs=pem.parse_file(server_certificates)

            logger.info(str(len(tmp_certs)) +" Zertifikate wurden empfangen bzw. eingelesen.")

            for crt in tmp_certs:
                self.x509_certs.append(load_pem_x509_certificate(str(crt).encode('ascii','ignore'),default_backend()))

            for x509 in self.x509_certs:
                self.certs.append(Certificate(x509,self.ca_file))

        except Exception as err:
            print err

    def __connect_ssl_socket(self,context):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        if self.proxy is None:
            ssl_sock = context.wrap_socket(s, server_hostname=self.hostname)
            ssl_sock.connect((self.hostname, self.port))
        else:
            try:
                s.connect(self.proxy)
            except socket.error, e:
                logger.error ( "Unable to connect to " + self.proxy[0]+":" + str(self.proxy[1]) + " " + str(e))
                exit(-1)
            s.send("CONNECT %s:%s HTTP/1.0\n\n" % (self.hostname, self.port))
            s.recv(1024)
            # logger.info ("Proxy response: " + string.strip(s.recv(1024)))
            ssl_sock = context.wrap_socket(s, server_hostname=self.hostname)
        return ssl_sock
        
