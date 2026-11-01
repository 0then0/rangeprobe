# Security policy

## Supported versions

Security fixes target the latest release. There are no separate maintenance branches and no
response-time commitment. Update before reporting a problem that may already be fixed.

## Reporting a vulnerability

Do not post exploit details, credentials or sensitive data in public issues or pull requests.

GitHub's private vulnerability reporting
([Report a vulnerability](https://github.com/0then0/rangeprobe/security/advisories/new)) is the
preferred channel, but it is **not enabled for this repository at the time of writing**. If the
link above does not work, open a public issue that only asks for a private contact channel, or
contact [@0then0](https://github.com/0then0) through a contact listed on their profile, and send the
details after a private channel exists. No email address or other contact is assumed.

Include the version (`rangeprobe version`), the command line with secrets removed, what you expected
the tool to do, and a minimal reproduction, for example a small server that triggers the problem.

## What counts

RangeProbe sends HTTP requests to a URL chosen by its user and reads local files that the user
names. Problems that matter here include:

- reading more than the configured request, byte or time limits;
- sending the user's headers or `If-Match` to another origin, downgrading HTTPS, or disabling TLS
  verification;
- leaking secrets, signed URLs or file contents into reports, output or error messages that the
  documentation says are redacted;
- markup injection or active content in the HTML report;
- overwriting or truncating files other than a report that the user asked for, or leaving a partial
  report that looks complete;
- crashes or hangs triggered by a hostile server's response.

Not in scope: a server that ignores or mishandles `Range` (that is what the tool reports),
denial of service by pointing the tool at a server you do not control, and findings that need
`--no-redact` or `--dump-mismatch` to leak the data those options exist to include.

RangeProbe is a diagnostic tool, not a security scanner or a sandbox. Do not point it at systems you
are not allowed to test.
