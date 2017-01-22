# TR-03116-4-checklist
Das Skript checklist.py überprüft einen TLS-Server auf Konformität zu den Vorgaben [TR-03116-4](https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Publikationen/TechnischeRichtlinien/TR03116/BSI-TR-03116-4.pdf?__blob=publicationFile&v=2) des Bundesamtes für Sicherheit in der Informationstechnik (BSI) . Es orientiert sich dabei an den Vorgaben der zugehörigen [Checkliste](https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Publikationen/TechnischeRichtlinien/TR03116/TLS-Checkliste.pdf?__blob=publicationFile&v=2).

**Aktuell ist das Skript noch in der Entwicklung. Es deckt fast alle Aspekte der Checkliste ab aber es gibt sicherlich noch viele kleine Baustellen. Auch müsste das Skript noch deutlich ausgiebiger getestet werden.**

## Systemvoraussetungen
* Python 2.7
* Installierte Python Pakete (pip install ...)
  * TLS
  * colorlog
* openssl binary (muss im Pfad liegen)
* SSLyze (muss im Pfad liegen)
* Unter OSX sollte https://github.com/raggi/openssl-osx-ca installiert sein

##Dateien
Folgende Dateien liegen in diesem Repository:

| Datei             | Inhalt                                                                                                                 |
|:------------------|:-----------------------------------------------------------------------------------------------------------------------|
| LICENSE.md        | Lizenzinformationen                                                                                                    |
| README.md         | diese Datei                                                                                                            |
| certificates.py   | In dieser Datei sind alle Prüfungen implementiert, die sich mit den vom Server präsentierten Zertifikaten beschäftigen |
| checklist.py      | Hauptdatei für die Implementierung                                                                                     |
| helper.py         | Hilfsfunktionen                                                                                                        |
| protocols.py      | In dieser Datei sind alle Prüfungen implementiert, die das TLS-Protokoll selbst betreffen                              |
| testuebersicht.md | Übersicht über alle Kriterien der Checkliste und ihre Abdeckung                                                        |
| tls_includes.py   | In dieser Datei sind einige Daten enthalten, die in den anderen Python-Dateien störten                                 |

##Anwendung
Der Aufruf erfolg mittels `python checklist.py servername port`

##Abdeckung der Kriterien
Eine Übersicht über die Kritierien der Checkliste und ihre Abdeckung ist in der Datei testfalluebersicht.md zu finden.

##Disclaimmer
**Der Code wurde grundlegend getestet aber aufgrund der Komplexität der Materie sollten die Ergebnisse des Skripts immer mit Vorsicht verwendet werden.**

##Beiträge
Fragen, Anmerkungen und Kommentare sind herzlich willkommen. Am Liebsten nehme ich natürlich Beiträge als Pull-Request.
