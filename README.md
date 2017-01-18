# TR-03116-4-checklist
Das Skript checklist.py überprüft einen TLS-Server auf Konformität zu den Vorgaben [TR-03116-4](https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Publikationen/TechnischeRichtlinien/TR03116/BSI-TR-03116-4.pdf?__blob=publicationFile&v=2) des Bundesamtes für Sicherheit in der Informationstechnik (BSI) . Es orientiert sich dabei an den Vorgaben der zugehörigen [Checkliste](https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Publikationen/TechnischeRichtlinien/TR03116/TLS-Checkliste.pdf?__blob=publicationFile&v=2).

Es werden nicht alle Aspekte der Checkliste vollständig und automatisch geprüft. Die folgende Tabelle gibt einen Überblick.

----------------------------------------------------
| Anforderung | Beschreibung                                     | Prüfung umgesetzt? | Hinweis                                                                                                                                                                                   |
|:------------|:-------------------------------------------------|:-------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| 2.3.1       | Es werden nur erlaubte TLS-Versionen unterstützt | Ja                 | Die Prüfung erfolgt durch eine Reihe von Verbindungsversuchen mit unterschiedlichen TLS-Versionen. Es wird die TLS-Library von python verwendet, die im Regelfall auf openssl zurückfällt |


## Systemvoraussetungen
* Python 2.7
* Installierte Python Pakete (pip install ...)
  * TLS
  * tbd
* openssl binary (muss im Pfad liegen)
-
