# TR-03116-4-checklist
Das Skript checklist.py überprüft einen TLS-Server auf Konformität zu den Vorgaben [TR-03116-4](https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Publikationen/TechnischeRichtlinien/TR03116/BSI-TR-03116-4.pdf?__blob=publicationFile&v=2) des Bundesamtes für Sicherheit in der Informationstechnik (BSI) . Es orientiert sich dabei an den Vorgaben der zugehörigen [Checkliste](https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Publikationen/TechnischeRichtlinien/TR03116/TLS-Checkliste.pdf?__blob=publicationFile&v=2).

** Aktuell ist das Skript noch in der Entwicklung. Es deckt fast alle Aspekte der Checkliste ab aber es gibt sicherlich noch viele kleine Baustellen. Auch müsste das Skript noch deutlich ausgiebiger getestet werden. **

## Systemvoraussetungen
* Python 2.7
* Installierte Python Pakete (pip install ...)
  * TLS
  * colorlog
* openssl binary (muss im Pfad liegen)
* SSLyze (muss im Pfad liegen)
* Unter OSX sollte https://github.com/raggi/openssl-osx-ca installiert sein

##Anwendung
In der Datei checklist.py müssen die Variablen hostname, port und ca_file gesetzt werden. Anschließend kann das Skript einfach mit python checklist.py gestartet werden.

##Disclaimmer
Der Code wurde grundlegend getestet aber aufgrund der Komplexität der Materie sollten die Ergebnisse des Skripts immer mit Vorsicht verwendet werden.

##Beiträge
Fragen, Anmerkungen und Kommentare sind herzlich willkommen. Am Liebsten nehme ich natürlich Beiträge als Pull-Request.
