# hesabo — verschlüsseltes E-Mail-Archiv auf next.hessenbox

Ein einzelnes, statisches Go-Binary (keine Runtime-Abhängigkeiten): holt E-Mail per
IMAP (Dovecot, Exchange, … — beliebig viele Konten), verschlüsselt sie client-seitig
mit [age](https://age-encryption.org) und legt sie als Content-addressed Blobs in
einem Ordner ab, den dein Nextcloud-Sync-Client (oder sonst ein Sync-Tool) in die
Cloud hochlädt.

```
IMAP (Konto 1..n: dovecot, Exchange, …)
   │  hesabo sync            ── Klartext nur im RAM der Maschine
   ▼
age-verschlüsselte Blobs
   ▼
~/Nextcloud/email-archive/   ── NC-Client synct die opaque .age-Dateien hoch
```

**Bedrohungsmodell:** Der Provider sieht nur verschlüsselte Blobs mit kryptographischen
Namen. Kein Inhalt, keine Betreffzeilen, keine Absender, keine Ordnerstruktur. Durch
Content-Addressing (Dateiname = SHA-256 des Klartexts) zahlt sich Deduplikation aus:
identische Mails (z. B. in mehreren Ordnern oder Konten) werden nur einmal gespeichert,
und ein erneuter Sync lädt nur Mails, die es noch nicht gibt — inkrementell wie ein
Backup-Tool. Daten sind gegen Korruption geschützt: age ist authentisiert, jede
Veränderung fällt bei `verify` auf.

## Bauen

```sh
go build -o hesabo .        # einzelnes Binary, kreuzkompilierbar (linux/darwin/windows)
```

## Einrichten (einmalig)

```sh
cp config.example.toml ~/.config/hesabo/config.toml
# Konten eintragen (so viele wie gewünscht). Alternativen für Passwörter:
#   password = "..."  oder  password_cmd = "cat ~/.config/imap-passwords/faculty"

hesabo keygen                            # erzeugt ~/.config/hesabo/key.txt  (WICHTIG: sichern!)
hesabo sync                              # erster Lauf
hesabo list                              # Probe: Header der archivierten Mails
```

Pfade lassen sich im TOML bzw. per `-config FILE` übersteuern.
`HESABO_CONFIG` setzt die Default-Config.

## Benutzung

```sh
hesabo sync [-account NAME]        # IMAP holen + verschlüsseln (inkrementell)
hesabo list   [-account NAME] [-limit 20]
hesabo search [-account NAME] TERM          # Volltextsuche über decodierte Mails
hesabo extract [-dir OUT] [-account NAME]   # entschlüsselte .eml-Dateien ausgeben
hesabo verify [-account NAME]               # jeden Blob entschlüsseln/prüfen
hesabo keygen [-output FILE]
```

## Betrieb / Automatisierung

```sh
crontab -e
# z. B. täglich um 03:00:
0 3 * * * $HOME/hesabo sync >> "$HOME/hesabo-sync.log" 2>&1
# monatlich prüfen:
@monthly $HOME/hesabo verify >> "$HOME/hesabo-verify.log" 2>&1
```

## Grundsätze

- **Append-only:** Es wird nie gelöscht. Auch wenn eine Mail auf dem Server weg ist,
  bleibt sie im Archiv — wie es sich für ein Archiv gehört.
- **Kein `\Seen`-Flag:** FETCH läuft mit `BODY.PEEK`, der Posteingang am Server bleibt unberührt.
- **Inkrementell & fortsetzbar:** UID/UIDVALIDITY-Stand in `state.json`; bei
  UIDVALIDITY-Wechsel wird der Ordner sauber neu geholt. Abgebrochene Läufe machen einfach dort weiter.
- **Konto-Typen optional:** `[[accounts]]` ist eine generische Liste. Dovecot- und
  Exchange-Konten sind nur Beispiele — jedes IMAP-Konto funktioniert, in jeder Kombination.

## Recovery

Schlüssel = `~/.config/hesabo/key.txt`. **Ohne diesen Schlüssel ist das Archiv
unlesbar** — Kopie in deinem Passwort-Manager aufbewahren. Zum Wiederherstellen auf
einem anderen Rechner: Binary + `config.toml` + `key.txt` ablegen, `hesabo extract`/`list`
gegen den synchronisierten Archiv-Ordner ausführen.

## Details

- IMAP-Client: [`emersion/go-imap/v2`](https://github.com/emersion/go-imap) (reines Go)
- Verschlüsselung: [`filippo.io/age`](https://age-encryption.org/v1) (X25519/ChaCha20-Poly1305, auditiert)
- Config: TOML
- Weitere Architektur-Entscheidungen: siehe `docs/arc42/`
