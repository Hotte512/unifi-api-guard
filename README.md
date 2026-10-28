# UniFi API Guard

Ein kleiner Rechte-Proxy für die **UniFi Network Integration API** (UniFi Network 9.4+).

UniFi-API-Keys kennen keine Berechtigungsstufen: Wer den Key hat, kann über die API das ganze Netzwerk ändern –
Firewall, VLANs, WLANs. UniFi API Guard sitzt zwischen deinen Anwendungen und dem Gateway. Er bekommt den echten
UniFi-Key, jede Anwendung bekommt einen **eigenen Key mit genau den Rechten, die sie braucht**.

**Anleitung:** [docs/anleitung.md](docs/anleitung.md) · **Änderungen:** [CHANGELOG.md](CHANGELOG.md)

```
NPMplus ──(Guard-Key: nur DNS-Einträge *.example.com)──┐
Home Assistant ──(Guard-Key: Geräte/Clients lesen)─────┼──► UniFi API Guard ──(UniFi-Key)──► UniFi-Gateway
Skript ──(Guard-Key: nur lesen)────────────────────────┘
```

## Funktionen

- **Gleiche API wie das Gateway:** Pfade unter `/proxy/network/integration/v1/` und Header `X-API-KEY` bleiben gleich.
  Anwendungen brauchen nur eine andere URL und einen anderen Key.
- **Regeln pro Key, alles andere ist verboten:** HTTP-Methoden × Endpunkt, optional mit **Objektfilter**
  (z. B. nur DNS-Einträge, deren `domain` auf `*.example.com` passt). Die Regeln werden im Formular gebaut:
  Endpunkt aus einer Liste der UniFi-Network-API oder eigener Pfad, Methoden per Häkchen. JSON bleibt als Expertenmodus.
  - Listen werden gefiltert (fremde Einträge sind unsichtbar, Paging stimmt weiter).
  - Fremde Einzelobjekte liefern `404`.
  - Beim Anlegen/Ändern wird der Body geprüft, beim Ändern/Löschen zusätzlich das bestehende Objekt –
    ein fremder Eintrag kann weder geändert, gelöscht noch „übernommen“ werden.
- **IP-Whitelist pro Key** (Pflicht; leer = gesperrt).
- **Vorlagen:** Lokale DNS-Einträge (z. B. für NPMplus), Nur lesen, Geräte und Clients lesen (z. B. Home Assistant),
  Eigene Regeln.
- **Rate-Limit pro Key**, Größen- und Zeitlimits für Anfragen.
- **Protokoll** der letzten Anfragen in der Oberfläche (Key-Name, IP, Methode, Pfad, erlaubt/abgelehnt).
  Keys und Request-Bodies werden nie geloggt.
- **Sicher gespeichert:** Guard-Keys nur als SHA-256-Hash (werden einmalig angezeigt), UniFi-Key AES-GCM-verschlüsselt,
  Admin-Passwort PBKDF2-SHA256, Konfigurationsdatei mit Rechten `0600`.
- **Gateway-Zertifikat:** Fingerprint-Pinning (empfohlen für selbstsignierte Zertifikate), CA-Prüfung oder aus.
- **Klein:** eine statische Go-Binärdatei ohne externe Abhängigkeiten, Distroless-Image ohne Shell, läuft als
  Nicht-Root-Benutzer.

## Start

```yaml
# compose.yaml
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
docker compose up -d
```

```bash
docker logs unifi-api-guard
```

Beim ersten Start legt der Guard ein **Einrichtungs-Token** an: in der Datei `setup-token` im Datenverzeichnis
(`cat data/setup-token`) und im Log. Admin-Oberfläche öffnen (`http://127.0.0.1:8081`), Token
eingeben und ein Admin-Passwort festlegen. Das Token ist danach wertlos.

Das Datenverzeichnis muss für den Container-Benutzer (UID 65532) beschreibbar sein:

```bash
mkdir -p data && sudo chown 65532:65532 data
```

## Zusammen mit NPMplus auf einem Host

Läuft der Guard auf demselben Host (oder LXC) wie NPMplus, ist der Host-Modus am einfachsten: Der Proxy lauscht nur
auf `127.0.0.1`, NPMplus nutzt `http://127.0.0.1:8090` und die erlaubte IP `127.0.0.1`.

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
```

Der [NPMplus-Hotte-Installer](https://github.com/Hotte512/NPMplus) (Branch `claude/hotte-ci`, `install/install.sh`
bzw. `install/proxmox.sh`) richtet das automatisch ein. Mehr in der [Anleitung](docs/anleitung.md).

## Einrichtung

1. **UniFi-Key erzeugen:** *UniFi Network › Einstellungen › Integrationen*. Am besten mit einem eigenen lokalen Admin.
2. **Gateway eintragen:** URL (z. B. `https://192.168.1.1`) und Key. „Fingerprint abrufen“, mit dem Zertifikat des
   Gateways vergleichen, speichern. „Verbindung testen“.
3. **Key für eine Anwendung anlegen:** Name, Vorlage, ggf. Domains, erlaubte IPs. Der Key wird nur einmal angezeigt.
   Mit der Vorlage „Eigene Regeln“ entsteht ein Key ohne Regeln, diese fügt man danach im Formular hinzu.

### NPMplus

Vorlage **„Lokale DNS-Einträge“**, Domains z. B. `*.example.com`, erlaubte IP = IP des NPMplus-Hosts
(z. B. `192.168.1.10`). In NPMplus unter *Einstellungen › UniFi Local DNS*:

| Feld | Wert |
| --- | --- |
| Gateway-URL | `http://192.168.1.x:8080` (Adresse des Guards) |
| API-Key | der Guard-Key (`uag_…`) |
| TLS prüfen | nach Guard-Konfiguration (bei HTTP egal) |

### Home Assistant

Vorlage **„Geräte und Clients lesen“** oder **„Nur lesen“**, erlaubte IP = Home Assistant. In der Integration bzw.
im REST-Sensor die Guard-URL und den Guard-Key verwenden.

## Regeln

Jeder Key hat eine Liste von Regeln (JSON, in der Oberfläche bearbeitbar). Pfade sind relativ zu
`/proxy/network/integration/v1/`; `*` steht für genau ein Segment, `**` am Ende für beliebig viele.

```json
[
  { "methods": ["GET"], "path": "sites" },
  { "methods": ["GET", "POST"], "path": "sites/*/dns/policies",
    "filter": { "field": "domain", "patterns": ["*.example.com"] } },
  { "methods": ["GET", "PUT", "DELETE"], "path": "sites/*/dns/policies/*",
    "filter": { "field": "domain", "patterns": ["*.example.com"] } }
]
```

Filtermuster: `example.com` = genau diese Domain, `*.example.com` = alle Subdomains (nicht `example.com` selbst),
`*` = alles.

## Konfiguration (Umgebungsvariablen)

| Variable | Standard | Bedeutung |
| --- | --- | --- |
| `GUARD_DATA_DIR` | `/data` | Konfiguration (`config.json`) und ggf. `secret.key` |
| `GUARD_PROXY_ADDR` | `:8080` | Proxy-Port für Anwendungen |
| `GUARD_ADMIN_ADDR` | `:8081` | Admin-Oberfläche |
| `GUARD_ADMIN_ALLOW` | private Netze | IPs/Netze, die die Admin-Oberfläche öffnen dürfen (kommagetrennt) |
| `GUARD_TRUSTED_PROXIES` | leer | Reverse-Proxys, deren `X-Forwarded-For` vertraut wird |
| `GUARD_SECRET_FILE` | `$GUARD_DATA_DIR/secret.key` | Schlüssel für die Verschlüsselung des UniFi-Keys (64 Hex-Zeichen, wird sonst erzeugt) |
| `GUARD_TLS_CERT`, `GUARD_TLS_KEY` | leer | HTTPS für beide Ports |
| `GUARD_COOKIE_SECURE` | `false` | `true`, wenn die Admin-Oberfläche hinter einem HTTPS-Reverse-Proxy läuft |

## Sicherheitshinweise

- Den **Admin-Port nicht ins Internet** und möglichst nur aus dem Admin-Netz erreichbar machen.
- Der Proxy-Port spricht standardmäßig HTTP. Im LAN meist ausreichend; sonst `GUARD_TLS_CERT`/`GUARD_TLS_KEY` setzen
  oder einen Reverse-Proxy davor.
- Liegt `secret.key` im selben Volume wie `config.json`, schützt die Verschlüsselung nur vor dem Auslesen der
  Konfigurationsdatei allein (z. B. in Backups). Besser: `GUARD_SECRET_FILE` auf ein Docker-Secret zeigen lassen.
- Wird der Guard kompromittiert, ist auch der UniFi-Key betroffen. Der Guard verkleinert das Risiko auf diesen einen,
  sehr kleinen Dienst – statt auf jede Anwendung, die die API nutzt.

## Entwicklung

```bash
go test -race ./...
```

```bash
go run ./cmd/unifi-api-guard
```

(mit `GUARD_DATA_DIR=./data`). Beispiele in Doku und Tests nur mit `example.com` und `192.168.1.x`.

## Haftungsausschluss und Hinweise

- **Keine Haftung, keine Gewähr.** Privates Hobby-Projekt, Nutzung auf eigenes Risiko. Der Guard verkleinert das
  Risiko eines UniFi-API-Keys, ersetzt aber keine eigene Prüfung der Regeln und keine Sicherung der
  Gateway-Konfiguration.
- **Mit KI-Unterstützung entwickelt.** Code und Doku entstehen mit Hilfe von KI (Claude), werden geprüft und
  getestet (Unit- und Ende-zu-Ende-Tests, `govulncheck`), können aber trotzdem Fehler enthalten.
- Nicht mit Ubiquiti verbunden. „UniFi“ ist eine Marke von Ubiquiti Inc.

> **English:** No warranty, no liability – use at your own risk. Developed with AI assistance (Claude); reviewed
> and tested, but mistakes are possible. Not affiliated with Ubiquiti.

## Lizenz

MIT, siehe [LICENSE](LICENSE).
