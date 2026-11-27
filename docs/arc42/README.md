# arc42 – cloud-email-archive (verschlüsseltes E-Mail-Archiv)

arc42-Template: https://arc42.org

| Metadatum | Wert |
|---|---|
| Autor | pi / cloud-email-archive |
| Stand | 2026 (Index-Runde) |
| Version | 0.1.0 |
| Status | Implementierung abgeschlossen, erste Produktion offen |

---

## 1. Einführung und Ziele

### 1.1 Aufgabenstellung

Ein verschlüsseltes E-Mail-Archiv persönlicher Postfächer (Universität/Fakultät:
Dovecot-IMAP; Verwaltung: Exchange-IMAP), abgelegt in einem Cloud-synchronisierten
Ordner — beliebiger Provider mit Sync-Client oder Mount: Nextcloud, Syncthing,
Dropbox, OneDrive, Google Drive, Seafile, SMB/NFS-Share, rclone-Mount; im Projekt-
fallback konkret: next.hessenbox per Nextcloud-Desktop-Client). Voraussetzungen:

- Provider (egal welcher) darf **keinen Klartext** sehen (kein Inhalt, keine
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
| Admin (Cloud-Provider) | keine unnötige Last, kein Klartext-Datenbestand |

---

## 2. Randbedingungen

| Bereich | Randbedingung |
|---|---|
| Konnektivität | IMAP4rev1/rev2 über TLS (993 implicit, alternativ STARTTLS) |
| Exchange | Basic-Auth oder App-Passwort; kein OAuth2 unterstützt (Randbedingung an Konto-Typ) |
| Cloud | Dateiordner-Sync oder Mount (Nextcloud, Syncthing, Dropbox, SMB/NFS, rclone …), keine Provider-API am Binary |
| Plattform | statisch gebautes Go-Binary, Windows/macOS/Linux |
| Krypto | age (X25519 + ChaCha20-Poly1305), kein eigenes Kryptoprotokoll |
| Recht | EU-DSGVO: Verschlüsselung als technische Maßnahme; Löschbarkeit → Schlüsselvernichtung |
| Deployment | Kein Package-Manager-Abhängigkeit, keine Systemdienste nötig (Cron genügt) |

---

## 3. Kontextabgrenzung

### 3.1 Fachlicher Kontext

```
┌─────────┐  IMAP/TLS   ┌──────────────┐   Dateiebene   ┌────────────────┐
│ IMAP-   │────────────▶│   cloud-email-archive     │ ──────────────▶│   Age-Blobs     │
│ Server  │             │   (Binary)   │                │ (im ArchiveDir)│
│ Dovecot │             └──────────────┘                └───────┬────────┘
│ Exchange│                                                      │ Sync des
└─────────┘   Passwörter + Schlüssel aus                        │ Sync-Clients
              $XDG_CONFIG_HOME/cloud-email-archive (außerhalb)                ▼
                                                   ┌───────────────────────┐
                                                   │ Cloud (z. B. Hessenbox)│
                                                   │ = opaque .age-Dateien │
                                                   └───────────────────────┘
```

### 3.2 Technischer Kontext

Eingänge (aktive Verbindungen): IMAP. Ausgänge: nur Dateisystem-Arbeiten im
ArchiveDir (`archive_dir`) sowie Schreibzugriff auf `state_file`/`key_file` in
`~/.config/cloud-email-archive`. Keine Netzwerk-Ausgänge außer IMAP.

---

## 4. Lösungsstrategie

- **Fetch:** `emersion/go-imap/v2` (imapclient) — robust, pure Go, unterstützt
  `BODY.PEEK` (kein `\Seen` setzen) und ReadOnly-SELECT.
- **Verschlüsselung:** `filippo.io/age` — standardisiertes, auditiertes
  Public-Key-Schema, pure Go, streaming.
- **Content-Addressing:** Dateiname = `<account>_<sha256(raw)>.age`. Ergibt
  Deduplikation (identische Mails → gleicher Name → Skip) und macht den Sync
  **inkrementell von Natur aus**, ohne eine separate Snapshot/Dedup-Datenbank.
- **State:** `state.json` mit (Account, Ordner, UIDVALIDITY, [UIDs], UID→Blobname). Plaintext-UIDs
  plus Ordner-Zuordnung
  sind kein Geheimnis; der Sync merkt sich nur, *was schon da ist*.
- **Append-only:** Löschung ist kein Anwendungsfall; Archiv bleibt vollständig.
- **Verifikation:** da age authentisiert ist, ist `verify` (alles entschlüsseln)

ein Vollbeweis der Archiv-Integrität — keine separate Checksummen-Tabelle nötig.

---

## 5. Bausteinsicht

```
cloud-email-archive
├── cmd/cea/main.go          thinner Entry-Point: main() -> app.Run
└── internal/app/            (package app — gesamte Anwendungslogik)
    ├── main.go              CLI-Dispatch (keygen|sync|index|list|search|extract|verify)
    ├── config.go            TOML-Config, Defaults, Konto-Auflösung
    ├── archive.go           Age-Layer: Blobname (SHA-256), put/get/walk, Header-Parsing
    ├── state.go             state.json Laden/Speichern (UIDVALIDITY/UIDs, UID→Blob → Ordner)
    ├── sync.go              IMAP-Sync: login/select/enumerate/fetch/encrypt (+ Index-Pflege)
    ├── view.go              list/search/extract/verify (lesend, offline)
    ├── index.go             Verschlüsselter Trigram-Index (.idx-<sha256>.age-Segmente,
    │                        Cache, Kompaktierung, Self-Heal; abgeleitete Daten)
    ├── lock.go/lock_stub.go Single-Writer-Lock (flock, Unix; No-op anderswo)
    └── *_test.go            Unit + In-Prozess-IMAP-Integrationstest, Fuzz-Targets,
                             Benchmarks (bench_test.go), Scale-Harness (scale_test.go),
                             Dovecot-Tier (dovecot_integration_test.go, -tags integration),
                             True-Binary-E2E (e2e_test.go)
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
nur durch den Sync-Client selbst.

**Lese-Kommandos (list/search/extract):** Blobs auflisten → entschlüsseln →
Header bzw. Volltext auswerten → ausgeben. `search` nutzt den verschlüsselten
Trigram-Index (`index.go`): nur die Postings des Suchterms werden gelesen,
Kandidaten-Blobs werden zur Bestätigung entschlüsselt; ohne/fallschädlichem
Index automatisch Fallback auf Rohscan (`search --raw` erzwingt ihn). Zahlen:
`docs/benchmark.md`. `verify`: jeden Blob entschlüsseln, Fehler zählen,
Exit-Code != 0 bei Korruption (Index-Dateien werden ignoriert).

---

## 7. Verteilungs-/Deploymentsicht

- Distribution: eine ausführbare Datei `cloud-email-archive` (GOOS/GOARCH-kombinierbar).
- Deployment: in `$HOME/cloud-email-archive` ablegen, Config nach `~/.config/cloud-email-archive/config.toml`.
- Automatisierung: Cron (täglich `sync`, monatlich `verify`). Kein Daemon nötig.
- Wiederherstellung: Binary + Config + Schlüssel auf neuem Rechner → `extract`.

---

## 8. Querschnittliche Konzepte

### 8.1 Sicherheit / Datenschutz

- Verschlüsselung client-seitig vor dem Sync; Provider sieht nur `.age`-Dateien.
  **Garantiert verschlüsselt:** Mail-Inhalte (Blobs) und Suchindex. Der Index-
  Dateiname ist ein reiner Hash; Blob-Dateinamen enthalten den Account-Namen im
  Klartext (bewusst: account-scoped Reads filtern vor der Entschlüsselung) plus
  SHA-256 als Dedup-Fingerprint; Anzahl/Größen der Mails bleiben sichtbar.
  **Keine Ordnerstruktur, keine Subjects, keine Absender** im Sync-Ordner.
- Alter: 256-Bit-X25519-Ephemeral-Key je Datei + ChaCha20-Poly1305 (age v1).
- Schlüssel-Passwort/„privater Teil": nur `key.txt`, 0600-Berechtigungen,
  außerhalb des Sync-Ordners. Verlust = Datenverlust (bewusste Trade-off, um keine
  Backdoor/Key-Escrow zu haben).
- Passwörter: via `password_cmd` aus 600er-Dateien (nicht in TOML), oder App-Passwort
  bei MFA-Exchange.
- Kein Klartext wird dauerhaft auf Platte geschrieben (nur in `extract`-Ausgabe, die
  der Nutzer explizit anfordert).
- **State verschlüsselt:** `state.json` liegt age-armored unter demselben
  Empfänger wie das Archiv und wird atomar geschrieben (verschlüsseln im
  Speicher, tmp+rename — kein Klartext-Fenster auf der Platte). Bestehende
  Klartext-States laden weiter (ohne Key) und migrieren beim nächsten Sync
  automatisch. Mit passphrasengeschütztem Key-File ist damit das komplette
  Metadaten-Bild verschlüsselt: die Ordnerhierarchie existiert nur im Speicher
  eines laufenden Kommandos.
- **Key-File optional passphrasengeschützt** (`keygen -passphrase`): Das
  Schlüsselmaterial liegt nie im Klartext auf der Platte — nur als age-armor
  an einen scrypt-Passphrase-Empfänger. Auflösung (lazy, nur bei Armored-Keys):
  `CEA_PASSPHRASE` → `passphrase_cmd` → verdeckte Terminals-Eingabe (x/term).
  Bewusst KEIN `-passphrase`-Flag: Kommandozeilen sind in ps/history sichtbar.
  Klartext-Keyfiles bleiben unverändert gültig.
- IMAP-Verbindung: Default IMAPS/implizites TLS (Port 993; Zertifikatsprüfung
  gegen den System-Store, TLS ≥ 1.2, kein InsecureSkipVerify — bewusst nicht
  konfigurierbar; Self-Signed-CAs via `SSL_CERT_FILE`). `security = "none"`
  wird laut gewarnt. Der verschlüsselte Pfad ist E2E getestet
  (TestSyncImplicitTLSEndToEnd: Handshake → Login → Fetch → State → Reconnect).

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
| Sync-Race mit dem Sync-Client (gleiche Datei gleichzeitig) | niedrig | atomare tmp+rename schreibt konsistente Blobs; der Client synct nach Abschluss |

---

## 12. Glossar

| Begriff | Bedeutung |
|---|---|
| age | modernes Datei-Verschlüsselungsformat (X25519 + ChaCha20-Poly1305) |
| Blob | eine verschlüsselte Nachricht: `<account>_<sha256>.age` |
| Content-Addressing | Dateiname = kryptografischer Hash des Inhalts |
| UID / UIDVALIDITY | IMAP-Konzepte zur stabilen Identifikation von Nachrichten/Postfächern |
| append-only | Archiv erweitert sich nur; nichts wird gelöscht |
| next.hessenbox | Hochschul-Nextcloud-Instanz — konkreter Beispiel-Provider |
