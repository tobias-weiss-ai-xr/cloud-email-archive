# arc42 – hesabo (verschlüsseltes E-Mail-Archiv)

arc42-Template: https://arc42.org

| Metadatum | Wert |
|---|---|
| Autor | pi / hesabo |
| Stand | 2026 |
| Version | 0.1.0 |
| Status | Implementierung abgeschlossen, erste Produktion offen |

---

## 1. Einführung und Ziele

### 1.1 Aufgabenstellung

Ein verschlüsseltes E-Mail-Archiv persönlicher Postfächer (Universität/Fakultät:
Dovecot-IMAP; Verwaltung: Exchange-IMAP), abgelegt in einem Cloud-synchronisierten
Ordner (next.hessenbox über den Nextcloud-Desktop-Client). Voraussetzungen:

- Provider (Nextcloud-Instanz) darf **keinen Klartext** sehen (kein Inhalt, keine
  Betreffzeilen, keine Absender, keine Ordnerstruktur, keine sprechenden Dateinamen).
- Lauffähig **überall** ohne installierte Runtime (ein statisches Binary), keine
  Betriebssystem-Integration (kein FUSE), keine Skript-Abhängigkeiten.
- Beide Postfachtypen sind **optional**; beliebige Kombination und Anzahl von Konten.
- Inkrementell, fortsetzbar, archivgerecht (append-only), überprüfbar.

### 1.2 Qualitätsziele

1. **Vertraulichkeit** gegenüber dem Cloud-Provider (authentisierte Verschlüsselung.
   Alter Datenschutz, Revisionssicherheit).
2. **Portabilität** — ein Binary, Kreuzkompilierung für Linux/macOS/Windows.
3. **Inkrementalität** — nur neue Nachrichten kosten Speicher/Zeit (Content-Addressing).
4. **Überprüfbarkeit** — Integrität des Archivs jederzeit beweisbar (`verify`).
5. **Schlüsselsicherheit** — Schlüssel und Passwörter liegen außerhalb des Sync-Ordners.

### 1.3 Stakeholder

| Stakeholder | Erwartung |
|---|---|
| Nutzer (Hochschulbeschäftigter) | Privatsphäre, einfache Bedienung, Recovery |
| Datenschutz | Keine personenbezogenen Daten beim Provider im Klartext |
| Admin (Hessenbox) | keine unnötige Last, kein Klartext-Datenbestand |

---

## 2. Randbedingungen

| Bereich | Randbedingung |
|---|---|
| Konnektivität | IMAP4rev1/rev2 über TLS (993 implicit, alternativ STARTTLS) |
| Exchange | Basic-Auth oder App-Passwort; kein OAuth2 unterstützt (Randbedingung an Konto-Typ) |
| Cloud | Dateiordner-Sync (Nextcloud Desktop), kein WebDAV-API am Binary |
| Plattform | statisch gebautes Go-Binary, Windows/macOS/Linux |
| Krypto | age (X25519 + ChaCha20-Poly1305), kein eigenes Kryptoprotokoll |
| Recht | EU-DSGVO: Verschlüsselung als technische Maßnahme; Löschbarkeit → Schlüsselvernichtung |
| Deployment | Kein Package-Manager-Abhängigkeit, keine Systemdienste nötig (Cron genügt) |

---

## 3. Kontextabgrenzung

### 3.1 Fachlicher Kontext

```
┌─────────┐  IMAP/TLS   ┌──────────────┐   Dateiebene   ┌────────────────┐
│ IMAP-   │────────────▶│   hesabo     │ ──────────────▶│   Age-Blobs     │
│ Server  │             │   (Binary)   │                │ (im ArchiveDir)│
│ Dovecot │             └──────────────┘                └───────┬────────┘
│ Exchange│                                                      │ Sync des
└─────────┘   Passwörter + Schlüssel aus                        │ NC-Clients
              $XDG_CONFIG_HOME/hesabo (außerhalb)                ▼
                                                   ┌───────────────────────┐
                                                   │ next.hessenbox (Cloud)│
                                                   │ = opaque .age-Dateien │
                                                   └───────────────────────┘
```

### 3.2 Technischer Kontext

Eingänge (aktive Verbindungen): IMAP. Ausgänge: nur Dateisystem-Arbeiten im
ArchiveDir (`archive_dir`) sowie Schreibzugriff auf `state_file`/`key_file` in
`~/.config/hesabo`. Keine Netzwerk-Ausgänge außer IMAP.

---

## 4. Lösungsstrategie

- **Fetch:** `emersion/go-imap/v2` (imapclient) — robust, pure Go, unterstützt
  `BODY.PEEK` (kein `\Seen` setzen) und ReadOnly-SELECT.
- **Verschlüsselung:** `filippo.io/age` — standardisiertes, auditiertes
  Public-Key-Schema, pure Go, streaming.
- **Content-Addressing:** Dateiname = `<account>_<sha256(raw)>.age`. Ergibt
  Deduplikation (identische Mails → gleicher Name → Skip) und macht den Sync
  **inkrementell von Natur aus**, ohne eine separate Snapshot/Dedup-Datenbank.
- **State:** `state.json` mit (Account, Ordner, UIDVALIDITY, [UIDs]). Plaintext-UIDs
  sind kein Geheimnis; der Sync merkt sich nur, *was schon da ist*.
- **Append-only:** Löschung ist kein Anwendungsfall; Archiv bleibt vollständig.
- **Verifikation:** da age authentisiert ist, ist `verify` (alles entschlüsseln)

ein Vollbeweis der Archiv-Integrität — keine separate Checksummen-Tabelle nötig.

---

## 5. Bausteinsicht

```
hesabo (package main)
 ├── main.go          CLI-Dispatch (keygen|sync|list|search|extract|verify)
 ├── config.go        TOML-Config, Defaults, Konto-Auflösung
 ├── archive.go       Age-Layer: Blobname (SHA-256), put/get/walk, Header-Parsing
 ├── state.go         state.json Laden/Speichern (UIDVALIDITY/UIDs)
 ├── sync.go          IMAP-Sync: login/select/enumerate/fetch/encrypt
 ├── view.go          list/search/extract/verify (lesend, offline)
 └── *-test.go        Unit + In-Prozess-IMAP-Integrationstest
```

### Abhängigkeiten

- `github.com/emersion/go-imap/v2` (imapclient, imap, imapserver nur im Test)
- `filippo.io/age`
- `github.com/BurntSushi/toml`
- Standard-Bibliothek (crypto/sha256, crypto/tls, …)

---

## 6. Laufzeitsicht

**Sync (Schritte pro Konto):** Dial (TLS nach Konfig) → Login → LIST (alle
selectbaren Ordner, Konfig filtert) → pro Ordner: SELECT (ReadOnly) →
UID-Enumeration der gegenwärtigen Nachrichten → Differenz gegen State →
`FETCH UID <set> (UID BODY.PEEK[])` → pro Nachricht: `age.Encrypt` → Blob
atomar schreiben (tmp + rename) → UID in State → State speichern.

Nebenläufigkeit: Konten sequenziell; ein Konto wird nie parallel abgefragt
(IMAP-Verbindungen sind pro Konto serialisiert). Schreibe-I/O in den Sync-Ordner
nur durch den NC-Client selbst.

**Lese-Kommandos (list/search/extract):** Blobs auflisten → entschlüsseln →
Header bzw. Volltext auswerten → ausgeben. `verify`: jeden Blob entschlüsseln,
Fehler zählen, Exit-Code != 0 bei Korruption.

---

## 7. Verteilungs-/Deploymentsicht

- Distribution: eine ausführbare Datei `hesabo` (GOOS/GOARCH-kombinierbar).
- Deployment: in `$HOME/hesabo` ablegen, Config nach `~/.config/hesabo/config.toml`.
- Automatisierung: Cron (täglich `sync`, monatlich `verify`). Kein Daemon nötig.
- Wiederherstellung: Binary + Config + Schlüssel auf neuem Rechner → `extract`.

---

## 8. Querschnittliche Konzepte

### 8.1 Sicherheit / Datenschutz

- Verschlüsselung client-seitig vor dem Sync; Provider sieht nur `.age`-Dateien mit
  Hash-Namen (keine Klartext-Metadaten, Größen bleiben natürlich sichtbar).
- Alter: 256-Bit-X25519-Ephemeral-Key je Datei + ChaCha20-Poly1305 (age v1).
- Schlüssel-Passwort/„privater Teil": nur `key.txt`, 0600-Berechtigungen,
  außerhalb des Sync-Ordners. Verlust = Datenverlust (bewusste Trade-off, um keine
  Backdoor/Key-Escrow zu haben).
- Passwörter: via `password_cmd` aus 600er-Dateien (nicht in TOML), oder App-Passwort
  bei MFA-Exchange.
- Kein Klartext wird dauerhaft auf Platte geschrieben (nur in `extract`-Ausgabe, die
  der Nutzer explizit anfordert).

### 8.2 Robustheit / Wiederaufnahme

- State schützt vor Doppelarbeit; abgebrochene Einzelnachrichten sind kostengünstig
  (nur ungeschriebene UIDs werden neu geholt).
- UIDVALIDITY-Wechsel → Ordner-Neustart von vorn (keine falschen Zuordnungen).
- `verify` als kontinuierliche Integritätsprüfung (Alter).

### 8.3 Portierbarkeit

- Reines Go; keine CGO; FUSE-frei; `os.UserConfigDir()` für plattformgerechte
  Konfig-Verzeichnisse; Pfade aus TOML absolut überschreibbar.

### 8.4 Validierung

- Unit-Tests: Archiv-Roundtrip, Content-Addressing, State, Header-Parsing,
  Key-Berechtigungen.
- Integrationstest: In-Prozess-IMAP-Server (go-imap `imapmemserver`) → echter
  Sync inkl. Inkrementalität.
- `go vet ./...` und `go test ./...` als Gate.

---

## 9. Architekturentscheidungen (ADR-Kurzform)

| # | Entscheidung | Begründung / Alternativen |
|---|---|---|
| 1 | age statt GPG/restic/gocryptfs | auditiert, ohne Laufzeit-Dependencies, streaming, pure Go — anders als restic (C-Binary) nicht einbettbar, anders als gocryptfs (FUSE) nicht überall lauffähig |
| 2 | Content-Addressing statt Snapshot-DB | Dedup + Inkrementalität ohne Indexdatei; Wiederanlauf trivial; Kosten: Dateiname trägt SHA (kein Geheimnis) |
| 3 | UID/UIDVALIDITY-State statt MODSEQ | universell kompatibel (auch ohne CONDSTORE), ausreichend für append-only |
| 4 | ein Binary, keine Daemons | „runs anywhere", keine Systemd/Service-Abhängigkeit, Cron statt Service |
| 5 | Konten als generische [[accounts]]-Liste | beide Typen optional, Kombination frei, zukunftsoffen (neue IMAP-Quellen) |
| 6 | Kein Löschen (append-only) | Archiv-Semantik; Revisionssicherheit; Datenschutz-Löschung = Schlüssel vernichten |

---

## 10. Qualitätsanforderungen

Szenarien (umgesetzt):
- **Q1 (Vertraulichkeit):** `verify` erkennt jede Manipulation; Provider-Zugriff
  liefert nur Blobs ohne Klartext-Hinweise.
- **Q2 (Inkrementalität):** 2. Sync nach Änderung nur der Neuzugänge; im Test belegt.
- **Q3 (Nutzbarkeit):** 6 CLI-Befehle; Recovery aus 3 Dateien dokumentiert.
- **Q4 (Korrektheit):** `go vet` + Unit/Integrationstests grün.

---

## 11. Technische Risiken

| Risiko | Bewertung | Gegenmaßnahme |
|---|---|---|
| Schlüssel-Verlust → Datenverlust | hoch | explizite Warnung bei `keygen`; Recovery-Doku; Passwortmanager |
| go-imap v2 ist Beta (API v2.0.0-beta.9) | mittel | Fixversion gepinnt in go.mod; API isoliert in sync.go |
| Exchange ohne Basic-Auth (nur OAuth2) | mittel | App-Passwort dokumentiert; falls Datenklasse-Zugriff über dedicated mailbox |
| Größen-Leak bei sehr großen Anhängen | niedrig | gewollter Trade-off; optionales `size`-Padding als Zukunftsthema |
| Sync-Race mit NC-Client (gleiche Datei gleichzeitig) | niedrig | atomare tmp+rename schreibt konsistente Blobs; NC synct nach Abschluss |

---

## 12. Glossar

| Begriff | Bedeutung |
|---|---|
| age | modernes Datei-Verschlüsselungsformat (X25519 + ChaCha20-Poly1305) |
| Blob | eine verschlüsselte Nachricht: `<account>_<sha256>.age` |
| Content-Addressing | Dateiname = kryptografischer Hash des Inhalts |
| UID / UIDVALIDITY | IMAP-Konzepte zur stabilen Identifikation von Nachrichten/Postfächern |
| append-only | Archiv erweitert sich nur; nichts wird gelöscht |
| next.hessenbox | Hochschul-Nextcloud-Instanz (Provider) |
