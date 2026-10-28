# Hinweise für Claude

Projekt: UniFi API Guard, Rechte-Proxy für die UniFi Network Integration API. Details: `README.md`.

- Go ohne externe Abhängigkeiten; vor jedem Push `gofmt -l .`, `go vet ./...`, `go test -race ./...`.
- Sicherheitsrelevante Änderungen (Regel-Engine, Pfadprüfung, Filter, Speicherung von Secrets) immer mit Tests.
- Keys, Passwörter und Request-Bodies dürfen nie geloggt werden.

## Pflicht bei jeder Änderung

- `CHANGELOG.md` ergänzen: Abschnitt mit dem heutigen Datum, Kategorien Neu / Geändert / Behoben / Sicherheit.
  Kurz und aus Nutzersicht formulieren.
- `README.md` und `docs/anleitung.md` aktualisieren, wenn sich Funktionen oder Bedienung ändern.

## Öffentliches Repository: keine internen Informationen

Nie in Code, Doku, Commit-Nachrichten, Issues, PRs oder Kommentare übernehmen, auch nicht aus Logs, Screenshots oder
Fehlermeldungen des Nutzers: echte Domains, Hostnamen, interne IPs, API-Keys/Tokens, Site-/Geräte-IDs,
E-Mail-Adressen, Namen, lokale Pfade. Beispiele nur mit `example.com` und `192.168.1.x`.
