# certfinder

`certfinder` recursively finds PEM and DER encoded X.509 certificates and reports each certificate's file,
subject, issuer, subject alternative names (SANs), extended key usage, certificate and SPKI fingerprints, and
validity period.

It uses only the Go standard library.

## Install

Homebrew on macOS:

```sh
brew install --cask krisiasty/tap/certfinder
```

Go 1.27 or newer is required:

```console
go install github.com/krisiasty/certfinder@latest
```

Tagged releases publish binaries for macOS, Linux, and Windows on AMD64 and ARM64. macOS releases also include
`.tar.gz` archives used by the Homebrew cask. Windows filenames include the `.exe` extension.

To build the current checkout instead:

```console
go build -o certfinder .
```

## Usage

```console
certfinder [options] PATH
certfinder --version
```

For example:

```console
certfinder /etc
certfinder -max-bytes 0 ./backup
certfinder -max-bytes 8388608 -workers 4 .
certfinder -usage=server -expiration=30d /etc/certificates
certfinder -expired /etc/certificates
certfinder -json /etc/certificates
```

Use `--version` to print the version, commit, and build timestamp.

The default scan initially reads at most the first 64 KiB of every regular file. This is enough to reject typical
large images, archives, databases, logs, and other unrelated data. If that prefix contains a valid PEM certificate,
`certfinder` rereads and parses the complete file so certificate bundles are never reported partially. Set
`-max-bytes 0` to inspect every file completely, or choose a larger positive sniffing limit when a certificate may
first appear later in a file.

There is an unavoidable tradeoff: no scanner can prove that an arbitrary file does not contain an embedded
certificate without inspecting the complete file. With a positive limit, `certfinder` may therefore miss a file
whose first PEM certificate is located after that limit. A DER certificate is recognized only when the complete
file fits within the limit because DER has no reliable text marker and parsing arbitrary binary offsets would
produce expensive false candidates.

Use `-usage` to select certificates that support a particular extended key usage. Common values are `server`,
`client`, `code-signing`, `email-protection`, `timestamping`, and `ocsp-signing`. The IPsec and Microsoft/Netscape
usage names shown in normal or JSON output are also accepted. Certificates without an extended key usage extension
are unrestricted and match every usage filter.

Use `-expiration=30d` to print certificates that are already expired or will expire within 30 days. Standard Go
duration units, such as `48h` or `90m`, are also accepted. `-expired` is a shortcut for `-expiration=0d`. The two
flags cannot be combined.

Directory symlinks are not followed. When `PATH` itself is a symlink to a regular file or directory, it is followed
once.

## Progress

At startup, `certfinder` writes its name, version, resolved scan path, worker count, and effective options to stderr.
A status line shows the number of files discovered and scanned, pending files, certificates found, and whether
directory discovery is complete. The periodic status refresh is limited to once every five seconds. The final
summary also reports how many files were stopped at the `-max-bytes` sniffing limit without triggering a full reread.

While directory discovery is running, the discovered-file total can increase. This keeps scanning single-pass and
avoids delaying the scan with a separate counting traversal. When a certificate is found in text mode, its details
replace the current terminal status line and a fresh status line is drawn beneath it. When stderr is redirected,
progress is emitted as ordinary lines without terminal control sequences.

Progress and structured logs use stderr. Certificate text and JSON use stdout, so `-json` output remains suitable
for piping to another program.

## Output

Each certificate is printed separately, including certificates in PEM bundles:

```text
/etc/example/server.pem
  Subject: CN=example.test,O=Example
  Issuer: CN=Example Internal CA,O=Example
  SANs: DNS:example.test, DNS:www.example.test, IP:192.0.2.10
  Extended key usage: client, server
  SHA-1 fingerprint: 27b1462e7158f9489d662e9e41c52c8211015681
  SHA-256 fingerprint: 8a1b7487ad907ebc857a079e25e941bb304077f5f488638efee6cc50ed09be85
  SPKI SHA-256 fingerprint: 9fd236c32ec4a2a645e25d80ef1af7961e3706e98f2b60479063c69ae302d7df
  Valid from: 2026-01-15T12:00:00Z
  Valid to: 2027-01-15T12:00:00Z
```

JSON groups the lowercase hexadecimal identifiers together:

```json
"fingerprints": {
  "sha1": "27b1462e7158f9489d662e9e41c52c8211015681",
  "sha256": "8a1b7487ad907ebc857a079e25e941bb304077f5f488638efee6cc50ed09be85",
  "spki_sha256": "9fd236c32ec4a2a645e25d80ef1af7961e3706e98f2b60479063c69ae302d7df"
}
```

SHA-1 is emitted only as a compatibility identifier for certificate-search ecosystems; it is not used for
certificate validation or other security decisions.

By default, server, client, dual-purpose, and unspecified-purpose certificates are all included. Pass `-json` to
emit the filtered results as a JSON array with snake-case field names and RFC 3339 timestamps. Runtime errors and
warnings use structured `slog` text records on stderr, so JSON written to stdout remains valid.
