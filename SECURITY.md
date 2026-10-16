# Security policy

## Reporting a vulnerability in evershield

If you find a way to make evershield leak data, execute untrusted code, reach
a network it should not, or produce a false negative that hides a real leak,
please report it privately first.

- Use GitHub's private vulnerability reporting on this repository
  (Security tab, "Report a vulnerability"), or
- email the maintainer at the address on the GitHub profile of
  [@inviy](https://github.com/inviy).

Please include the version, a minimal reproduction, and what you expected.
You will get an acknowledgement within a few days and a fix or a reasoned
response as soon as practical. Credit is given unless you prefer otherwise.

## Scope notes

- evershield runs locally and makes network requests only to origins you
  list in its configuration. A request to any other origin is a bug; report
  it.
- Findings about **your own application** are not vulnerabilities in
  evershield. Fix them in your application.
- Please do not use evershield, or report findings from it, against systems
  you are not authorised to test.
