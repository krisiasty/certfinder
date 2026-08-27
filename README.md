# certfinder

`certfinder` recursively finds PEM and DER encoded X.509 certificates and reports each certificate's file,
identity, purpose, cryptographic properties, certificate and SPKI fingerprints, and validity state.

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
certfinder -hostname=service.example.test /etc/certificates
certfinder -hostname=192.0.2.10 -json /etc/certificates
certfinder -expired /etc/certificates
certfinder -json /etc/certificates
certfinder -jsonl -quiet /etc/certificates
certfinder -unique /etc/certificates
certfinder -duplicates -json /etc/certificates
certfinder -usage=server -fail-expiring=30d -quiet /etc/certificates
certfinder -exclude=.git -exclude='build/*' .
certfinder -extensions=.pem,.crt -extensions=cer /etc
certfinder -one-file-system -ignore-errors /
certfinder -follow-symlinks /etc/services
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

Use `-hostname=service.example.test` to print only certificates valid for a DNS name, or provide an IPv4 or IPv6
address to match an IP SAN. Matching uses Go's `x509.Certificate.VerifyHostname`, including case-insensitive DNS
names and left-most-label wildcards in certificate SANs. The supplied filter is a concrete service name, not a
wildcard pattern, and the legacy Common Name is ignored. This filter composes with `-usage`, `-expiration`, and
`-expired`, and selects the same certificates in text, JSON, and JSON Lines output.

## Expiration filtering versus monitoring

The expiration flags form two separate pairs. The filter flags control which certificates are printed, while the
monitoring flags control the exit status without hiding certificates from the output.

| Flag | Effect on output | Effect on exit status |
| --- | --- | --- |
| `-expired` | Print only already expired certificates. | None. |
| `-expiration=30d` | Print certificates that are already expired or expire within 30 days. | None. |
| `-fail-expired` | Do not filter the output. | Return status `3` if a selected certificate is expired. |
| `-fail-expiring=30d` | Do not filter output. | Status `3` for expiry within 30 days, including expired certificates. |

For example, the first command prints only expired certificates. The second prints every certificate selected by
the other filters, but returns status `3` if any of them is expired:

```console
certfinder -expired /etc/certificates
certfinder -fail-expired /etc/certificates
```

`-expired` is a shortcut for `-expiration=0d`, and `-fail-expired` is a shortcut for `-fail-expiring=0d`. A shortcut
cannot be combined with its duration-based counterpart. Durations use standard Go units, such as `48h` or `90m`,
with `d` additionally accepted for days.

## Monitoring and exit statuses

Monitoring applies after the existing selection filters. For example, `-usage=server -fail-expired` ignores expired
certificates that are restricted to client authentication. Adding `-expiration=7d` further limits both output and
monitoring to certificates selected by that seven-day window.

Exit statuses are:

- `0`: scan completed without a monitored finding.
- `1`: runtime, traversal, scan, or output error.
- `2`: invalid command-line usage.
- `3`: at least one matching certificate crossed the requested monitoring threshold.

Runtime errors take precedence over operational findings. With `-ignore-errors`, non-fatal path errors remain visible
as warnings but do not override status `3`.

## Filesystem traversal

Use repeatable `-exclude=GLOB` options to skip files or prune directories before they are traversed. Patterns are
matched against paths relative to the scan root using `/` separators on every operating system. A pattern containing
`/` matches the complete relative path. A pattern without `/`, such as `.git` or `cache`, matches a file or directory
name at any depth. Globs use Go `path.Match` syntax: `*`, `?`, and character classes do not cross `/` separators.

Use `-extensions=.pem,.crt` to scan only files with the listed final extensions. The flag is case-insensitive, accepts
extensions with or without a leading dot, and may be repeated. Extension filtering is disabled by default because a
valid certificate can have any filename.

Directory and file symlinks encountered below `PATH` are skipped by default. `-follow-symlinks` follows them while
tracking canonical directory targets, preventing cycles and scanning each target directory at most once. When `PATH`
itself is a symlink to a regular file or directory, it is always followed once.

On Linux and macOS, `-one-file-system` compares device identifiers and skips files and directory trees located on a
different filesystem from `PATH`. Other platforms return a clear unsupported-option error when the flag is used.

By default, any file or traversal error makes the command exit unsuccessfully after all accessible files have been
scanned. `-ignore-errors` preserves warnings and the final error count but returns success for these non-fatal errors.
Invalid options and failures inspecting the scan root remain fatal.

## Duplicate detection

By default, output remains occurrence-based: every matching certificate in every file or bundle position is printed.
Certificate identity is the SHA-256 fingerprint of the raw DER certificate, so certificates with similar metadata
but different encodings are not grouped together.

Use `-unique` to print one group for each matching fingerprint. Use `-duplicates` to print only groups with at least
two occurrences. Both modes list every source path and its zero-based certificate index. Repeated entries in one PEM
bundle count as separate locations, as do copies in different files.

Selection filters such as `-usage`, `-hostname`, `-expiration`, and `-expired` are applied before grouping. Monitoring
flags are evaluated against the same matching occurrences. `-unique` and `-duplicates` cannot be combined.

Grouped modes require the complete result set to produce deterministic path and index ordering. They therefore work
with text and `-json` output but cannot be combined with streaming `-jsonl`. Use `-json` when grouped structured output
is required.

Grouped JSON uses a separate, unambiguous schema with certificate metadata and a complete location list. For example,
an abridged duplicate record looks like this:

```json
{
  "certificate": {
    "subject": "CN=service.example.test",
    "fingerprints": {
      "sha256": "57ddc5f785d733d2644396f55208842948a73c3b022346f106d43927be4bf8ee"
    }
  },
  "locations": [
    {"path": "/etc/service.pem", "index": 0},
    {"path": "/etc/ca-bundle.pem", "index": 12}
  ]
}
```

## Progress

At startup, `certfinder` writes its name, version, resolved scan path, worker count, and all effective scan and
traversal options to stderr. A status line shows the number of files discovered and scanned, pending files,
certificates found, and whether directory discovery is complete. The periodic status refresh is limited to once
every five seconds. The final summary also reports how many files were stopped at the `-max-bytes` sniffing limit
without triggering a full reread. Certificate identity counts are calculated after selection filters: `matched` is
the number of matching occurrences, `unique` is the number of distinct SHA-256 fingerprints, and each occurrence
after the first copy of a fingerprint is a `duplicate occurrence`.

While directory discovery is running, the discovered-file total can increase. This keeps scanning single-pass and
avoids delaying the scan with a separate counting traversal. When a certificate is found in text mode, its details
replace the current terminal status line and a fresh status line is drawn beneath it. When stderr is redirected,
progress is emitted as ordinary lines without terminal control sequences.

Progress and structured logs use stderr. Certificate text, JSON, and JSON Lines use stdout, so structured output
remains suitable for piping to another program. `-quiet` suppresses startup information, progress updates, and the
final summary while preserving certificate output, warnings, and errors.

## Output

Each certificate is printed separately, including certificates in PEM bundles:

```text
/etc/example/server.pem
  Subject: CN=example.test,O=Example
  Issuer: CN=Example Internal CA,O=Example
  Serial number: 5f43a21b
  Certificate type: leaf
  Self-signed: no
  SANs: DNS:example.test, DNS:www.example.test, IP:192.0.2.10
  Key usage: digital-signature, key-encipherment
  Extended key usage: client, server
  Public key: RSA (2048 bits)
  Signature algorithm: SHA256-RSA
  SHA-1 fingerprint: 27b1462e7158f9489d662e9e41c52c8211015681
  SHA-256 fingerprint: 8a1b7487ad907ebc857a079e25e941bb304077f5f488638efee6cc50ed09be85
  SPKI SHA-256 fingerprint: 9fd236c32ec4a2a645e25d80ef1af7961e3706e98f2b60479063c69ae302d7df
  Valid from: 2026-01-15T12:00:00Z
  Valid to: 2027-01-15T12:00:00Z
  Validity status: valid
```

Serial numbers use lowercase hexadecimal. The certificate type is `CA` or `leaf`. Self-signed status requires both
matching subject and issuer names and a valid signature made by the certificate's own public key. Public-key output
includes the RSA key size or ECDSA curve where applicable.

JSON exposes the same health metadata with typed snake-case fields and groups the lowercase hexadecimal identifiers
together:

```json
{
  "serial_number": "5f43a21b",
  "is_ca": false,
  "self_signed": false,
  "key_usage": ["digital-signature", "key-encipherment"],
  "public_key": {
    "algorithm": "RSA",
    "bits": 2048
  },
  "signature_algorithm": "SHA256-RSA",
  "fingerprints": {
    "sha1": "27b1462e7158f9489d662e9e41c52c8211015681",
    "sha256": "8a1b7487ad907ebc857a079e25e941bb304077f5f488638efee6cc50ed09be85",
    "spki_sha256": "9fd236c32ec4a2a645e25d80ef1af7961e3706e98f2b60479063c69ae302d7df"
  },
  "validity_status": "valid"
}
```

SHA-1 is emitted only as a compatibility identifier for certificate-search ecosystems; it is not used for
certificate validation or other security decisions.

By default, server, client, dual-purpose, and unspecified-purpose certificates are all included. Pass `-json` to
emit the filtered results as a sorted JSON array with snake-case field names and RFC 3339 timestamps. Array output is
written after scanning finishes and is convenient when one complete, deterministic JSON document is required.

Pass `-jsonl` to emit each matching certificate immediately as one compact JSON object followed by a newline. JSON
Lines output has no enclosing array, uses bounded certificate memory, and follows worker completion order rather than
sorted path order. Complete lines remain usable if a scan is interrupted. A scan with no matches emits no JSON Lines
records. `-json` and `-jsonl` cannot be combined.

For example, use `jq '.[]' results.json` with array JSON and `jq '.' results.jsonl` with JSON Lines. Runtime errors and
warnings use structured `slog` text records on stderr, so structured stdout remains valid.
