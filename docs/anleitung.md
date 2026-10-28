# Anleitung

Schritt für Schritt von der Installation bis zum ersten Key. Alle Beispiele nutzen `example.com` und `192.168.1.x`.

## Was der Guard macht

UniFi-API-Keys kennen keine Berechtigungen: Wer den Key hat, darf alles. UniFi API Guard bekommt den echten Key und
gibt jeder Anwendung einen eigenen Guard-Key, der nur die freigegebenen Aufrufe erlaubt. Anfragen anderer Art, von
fremden IPs oder auf fremde Objekte werden abgelehnt oder gefiltert.

```text
NPMplus        ──(Guard-Key A)──┐
Home Assistant ──(Guard-Key B)──┼──► UniFi API Guard ──(UniFi-Key)──► UniFi-Gateway
Skript         ──(Guard-Key C)──┘
```

## 1. Installation

### Mit Docker Compose (allgemein)

```yaml
services:
  unifi-api-guard:
    image: ghcr.io/hotte512/unifi-api-guard:latest
    container_name: unifi-api-guard
    restart: unless-stopped
    ports:
      - "8080:8080"            # Proxy für Anwendungen
      - "127.0.0.1:8081:8081"  # Admin-Oberfläche
    volumes:
      - ./data:/data
```

```bash
mkdir -p data && sudo chown 65532:65532 data
docker compose up -d
```

### Empfohlen: auf demselben Host bzw. LXC wie NPMplus

Der Guard läuft im Host-Netzwerk und lauscht auf `127.0.0.1`, NPMplus erreicht ihn ohne Umweg über Docker-Netze.
Der Proxy-Port ist dann von außen nicht erreichbar.

```yaml
services:
  unifi-api-guard:
    image: ghcr.io/hotte512/unifi-api-guard:latest
    container_name: unifi-api-guard
    restart: unless-stopped
    network_mode: host
    environment:
      GUARD_PROXY_ADDR: 127.0.0.1:8090
      GUARD_ADMIN_ADDR: :8091
    volumes:
      - /opt/unifi-api-guard:/data
```

```bash
sudo mkdir -p /opt/unifi-api-guard && sudo chown 65532:65532 /opt/unifi-api-guard
docker compose up -d
```

Die Admin-Oberfläche ist dann unter `http://192.168.1.x:8091` erreichbar (nur aus privaten Netzen, siehe
`GUARD_ADMIN_ALLOW` in der README).

Das Repository [NPMplus Hotte](https://github.com/Hotte512/NPMplus) (Branch `claude/hotte-ci`) enthält einen
Installer, der genau dieses Setup automatisch einrichtet: `install/install.sh` (auf dem Host) und
`install/proxmox.sh` (neuer LXC auf Proxmox). Details in `docs/installation.md` dort.

## 2. Erster Start

1. Einrichtungs-Token holen – es steht in der Datei `setup-token` im Datenverzeichnis und im Log:

   ```bash
   cat /opt/unifi-api-guard/setup-token
   ```

   ```bash
   docker logs unifi-api-guard 2>&1 | grep setup_token
   ```

   Gibt es beides nicht, läuft der Guard nicht richtig (siehe Fehlersuche, meist falscher Besitzer des
   Datenverzeichnisses).

2. Admin-Oberfläche öffnen, unter „Einrichtung“ das Token eingeben und ein Admin-Passwort (mind. 12 Zeichen)
   festlegen. Danach ist das Token wertlos, die Datei `setup-token` wird gelöscht.

## 3. Gateway eintragen

1. In UniFi Network unter *Einstellungen › Integrationen* einen API-Key erzeugen, am besten mit einem eigenen
   lokalen Admin.
2. Im Guard unter „Gateway“ die URL (z. B. `https://192.168.1.1`) und den UniFi-Key eintragen.
3. „Fingerprint abrufen“ klicken und den angezeigten Fingerprint mit dem Zertifikat des Gateways vergleichen.
4. „Speichern“, danach „Verbindung testen“. Erwartet wird „Verbindung ok, … Site(s) gefunden.“

## 4. Key anlegen

*Neuer Key* öffnen und ausfüllen:

- **Name**, z. B. `NPMplus`.
- **Vorlage:** Lokale DNS-Einträge, Nur lesen, Geräte und Clients lesen oder Eigene Regeln.
- **Erlaubte Domains** (nur bei „Lokale DNS-Einträge“): `*.example.com` = alle Subdomains, `example.com` = nur
  genau diese Domain.
- **Erlaubte IP-Adressen / Netze:** eine pro Zeile. Leer bedeutet: Key gesperrt.
- **Anfragen pro Minute** (0 = unbegrenzt).

Mit „Key erzeugen“ wird der Key **nur einmal** angezeigt. Sofort kopieren, er wird nicht gespeichert.

Bei der Vorlage **„Eigene Regeln“** hat der Key noch keine Regeln und darf deshalb nichts. Die Regeln legt man im
Anschluss unter „Regeln ansehen und bearbeiten“ an (Abschnitt 6).

## 5. Anwendungen verbinden

### NPMplus

Vorlage „Lokale DNS-Einträge“ mit deinen Domains.

| Setup | Gateway-URL in NPMplus | Erlaubte IP im Key |
| --- | --- | --- |
| Gleicher Host (Host-Modus) | `http://127.0.0.1:8090` | `127.0.0.1` |
| Anderer Host | `http://192.168.1.x:8080` (Adresse des Guards) | IP des NPMplus-Hosts, z. B. `192.168.1.10` |

Als API-Key den Guard-Key eintragen.

### Home Assistant

Vorlage „Geräte und Clients lesen“ (oder „Nur lesen“), erlaubte IP = IP von Home Assistant. In der Integration bzw.
im REST-Sensor die Guard-URL und den Guard-Key verwenden.

### Eigene Skripte

```bash
curl -H "X-API-KEY: uag_..." http://192.168.1.x:8080/proxy/network/integration/v1/sites
```

Die API ist identisch zum Gateway, nur URL und Key unterscheiden sich.

## 6. Regeln bearbeiten

Unter *Übersicht › Name des Keys* stehen die Regeln. Alles, was keine Regel erlaubt, ist verboten. Leere Regeln
werden ignoriert.

Jede Regel hat diese Felder:

| Feld | Bedeutung |
| --- | --- |
| Endpunkt | Auswahl aus der Liste der UniFi-Network-API, gruppiert (Geräte, Clients, Netzwerke, WLAN, DNS, Firewall, …), oder „Eigener Pfad“ |
| Eigener Pfad | nur bei „Eigener Pfad“, relativ zu `/proxy/network/integration/v1/`; `*` = genau ein Segment, `**` am Ende = beliebig viele, z. B. `sites/*/dns/policies`. Anfragen mit anderen Zeichen als Buchstaben, Ziffern und `-._~` in einem Segment lehnt der Guard immer mit `400` ab |
| Erlaubte Methoden | Häkchen bei lesen (GET), anlegen (POST), ersetzen (PUT), ändern (PATCH), löschen (DELETE); nicht unterstützte Methoden des Endpunkts sind ausgegraut |
| Filter-Feld (optional) | Feld des Objekts, das geprüft wird, z. B. `domain` |
| Muster | eins pro Zeile; `example.com` = genau diese Domain, `*.example.com` = alle Subdomains (nicht `example.com` selbst), `*` = alles |

„Regel entfernen“ löscht die Regel beim Speichern. „Weitere Regel“ fügt eine leere Regel hinzu. Ohne JavaScript
werden immer zwei leere Regeln angezeigt; für mehr Regeln speichert man und bearbeitet danach erneut.

Beispiel: Sites lesen, DNS-Einträge nur für `*.example.com` lesen, anlegen, ändern und löschen.

| Endpunkt | Methoden | Filter |
| --- | --- | --- |
| Sites (Liste) | lesen | – |
| DNS-Policies (Liste / anlegen) | lesen, anlegen | Feld `domain`, Muster `*.example.com` |
| DNS-Policy (einzeln) | lesen, ersetzen, löschen | Feld `domain`, Muster `*.example.com` |

### Filter gelten nur für Objekte mit dem Feld

Ein Filter prüft das Feld im Objekt. Fehlt das Feld im Body oder im bestehenden Objekt, wird die Anfrage abgelehnt.
Beispiel: Ein PATCH auf Firewall-Policies enthält nur `loggingEnabled`, kein `name`. Mit einem Filter auf `name`
wird dieser PATCH daher abgelehnt, ohne Filter ist er erlaubt.

Auch die Reihenfolge-Endpunkte (`sites/*/firewall/policies/ordering`, `sites/*/acl-rules/ordering`) passen auf das
Muster `…/*`. Eine Regel mit Filter auf `…/policies/*` lehnt die Reihenfolge deshalb ab. Wer die Reihenfolge ändern
will, braucht dafür eine eigene Regel ohne Filter.

### Expertenmodus: JSON

Unter „JSON bearbeiten (Experten)“ stehen die Regeln als JSON. Mit dem Schalter darunter wird beim Speichern
festgelegt, ob das Formular oder das JSON gilt; „JSON“ ersetzt alle Regeln.

```json
[
  { "methods": ["GET"], "path": "sites" },
  { "methods": ["GET", "POST"], "path": "sites/*/dns/policies",
    "filter": { "field": "domain", "patterns": ["*.example.com"] } },
  { "methods": ["GET", "PUT", "DELETE"], "path": "sites/*/dns/policies/*",
    "filter": { "field": "domain", "patterns": ["*.example.com"] } }
]
```

| Feld | Bedeutung |
| --- | --- |
| `methods` | erlaubte HTTP-Methoden (GET, POST, PUT, PATCH, DELETE) |
| `path` | Pfad relativ zu `/proxy/network/integration/v1/` |
| `filter.field` | Feld des Objekts, das geprüft wird (hier `domain`) |
| `filter.patterns` | erlaubte Werte, Schreibweise wie oben |

Listen zeigen nur passende Einträge, fremde Einzelobjekte liefern `404`, beim Anlegen/Ändern wird der Body geprüft.

## 7. Fehlersuche

Zuerst in der Übersicht unter „Letzte Anfragen“ nachsehen: dort stehen Key, echte Quell-IP, Anfrage und Grund.

| Meldung | Ursache | Lösung |
| --- | --- | --- |
| Kein Einrichtungs-Token, Container startet immer wieder neu, im Log `permission denied` | Datenverzeichnis gehört nicht UID 65532 | `chown 65532:65532 /opt/unifi-api-guard && docker restart unifi-api-guard`, dann `cat /opt/unifi-api-guard/setup-token` |
| Kein Einrichtungs-Token, Admin-Oberfläche zeigt die Anmeldung | Es gibt schon ein Admin-Passwort | Mit dem Passwort anmelden oder „Admin-Passwort vergessen“ |
| `401` `invalid api key` | Key falsch, gelöscht oder Leerzeichen kopiert | Key prüfen, sonst neuen anlegen |
| `403` `ip address not allowed for this api key` | Quell-IP steht nicht in den erlaubten IPs | Echte IP unter „Letzte Anfragen“ ablesen und eintragen, bei Docker-Bridge z. B. `172.17.0.1` |
| `403` `not allowed for this api key` | Keine Regel erlaubt Methode und Pfad | Regel ergänzen (Abschnitt 6) |
| `403` `domain not allowed for this api key` | Body passt nicht zum Objektfilter oder enthält das Filterfeld nicht | Domain in den Mustern ergänzen, sonst Filter entfernen oder eigene Regel ohne Filter anlegen (Abschnitt 6) |
| `404` bei einem Objekt | Objekt liegt außerhalb des Filters (für diesen Key unsichtbar) | Filtermuster prüfen |
| `502` `upstream ...` | Gateway nicht erreichbar oder nicht konfiguriert | URL, UniFi-Key und Fingerprint prüfen, „Verbindung testen“ |
| Admin-Oberfläche: `403 forbidden` | Zugriff aus einem Netz außerhalb von `GUARD_ADMIN_ALLOW` | Netz in `GUARD_ADMIN_ALLOW` aufnehmen |

Wer vermutet, dass jemand eine Sitzung übernommen hat, ändert unter „Passwort“ das Admin-Passwort. Das meldet alle
anderen Sitzungen ab.

### Admin-Passwort vergessen

1. Container stoppen: `docker stop unifi-api-guard`
2. In `/data/config.json` (im Beispiel `/opt/unifi-api-guard/config.json`) den Wert bei `"admin_password"` leeren, also
   `"admin_password": ""`.
3. Container starten: `docker start unifi-api-guard`
4. Neues Einrichtungs-Token aus `/opt/unifi-api-guard/setup-token` (oder dem Log) holen und damit ein neues Passwort setzen.

## 8. Update und Backup

Update:

```bash
docker compose pull && docker compose up -d
```

Backup: `config.json` und `secret.key` aus dem Datenverzeichnis gehören zusammen. Ohne `secret.key` lässt sich der
gespeicherte UniFi-Key nicht mehr entschlüsseln. Beide Dateien enthalten Geheimnisse, also sicher aufbewahren.
