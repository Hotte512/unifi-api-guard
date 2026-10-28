# Changelog

Alle Änderungen an UniFi API Guard. Format angelehnt an Keep a Changelog, Einträge nach Datum.

Kategorien: Neu / Geändert / Behoben / Sicherheit.

## 2026-10-28

### Neu

- Erste Version: Rechte-Proxy für die UniFi Network Integration API mit eigenem Key pro Anwendung.
- Gleiche API wie das Gateway (Pfade und Header `X-API-KEY`), Anwendungen brauchen nur eine andere URL und einen anderen Key.
- Regeln pro Key (Methoden × Pfadmuster) mit Objektfilter, z. B. nur DNS-Einträge für `*.example.com`; fremde Einträge sind unsichtbar oder liefern `404`.
- Pflicht-IP-Whitelist und Rate-Limit pro Key.
- Vorlagen: Lokale DNS-Einträge (NPMplus), Nur lesen, Geräte und Clients lesen (Home Assistant), Eigene Regeln.
- Admin-Oberfläche mit Einrichtungs-Token, Gateway-Einstellungen (Fingerprint-Pinning, Verbindungstest), Key-Verwaltung und Protokoll der letzten Anfragen.
- Sichere Speicherung: Guard-Keys nur als Hash, UniFi-Key verschlüsselt, Keys und Request-Bodies werden nie geloggt.
- Anleitung für die Einrichtung, auch zusammen mit NPMplus auf einem Host: `docs/anleitung.md`.

### Geändert

- README: Haftungsausschluss und Hinweis auf die Entwicklung mit KI-Unterstützung.
- Das Einrichtungs-Token steht zusätzlich in der Datei `setup-token` im Datenverzeichnis und wird nach der
  Einrichtung gelöscht – es geht also nicht mehr verloren, wenn das Container-Log weg ist.
- CI prüft mit dem neuesten Go-1.26-Patch-Release und nutzt neuere GitHub-Actions-Versionen.

### Behoben

- Ist das Datenverzeichnis nicht beschreibbar (falscher Besitzer), nennt die Fehlermeldung jetzt den nötigen
  `chown`-Befehl statt nur „permission denied“.
