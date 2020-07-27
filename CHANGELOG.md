# pbgpp Version Changelog

**Version 0.2.1** - First GitHub release

**Version 0.2.2** - New directory structure, Support for Large Communities, PyPI package release

**Version 0.2.3** - Adding negated filtering

**Version 0.2.4** - Fixing parsing bug of OPEN messages

**Version 0.2.5** - Fixing minor version bug

**Version 0.2.6** - Adding JSON formatter for OPEN messages

**Version 0.2.7** - Adding OPEN message fields for line based output (ASN, Hold Time, Version, BGP Identifier)

**Version 0.2.8** - Adding prefix length field for line based output

**Version 0.2.9** - Adding SLL-packet support (Linux cooked-packet), Fixing copyright notice

**Version 0.2.10** - Adding support for wildcards for pcap file argument, adding field aliases, minor bug fix

**Version 0.2.11** - Fixing bug that causes trouble with missing tabs in line-based output

**Version 0.2.12** - Removing functionless progress-flag; the function itself were already removed before first GitHub release

**Version 0.2.13** - Fixing bug within community filter

**Version 0.2.14** - Fixed output problems with the old LineBased Formatter

**Version 0.2.15** - Tagged version with the old LineBased Formatter + several bug fixes for it

**Version 0.2.16** - Adding a new LineBased Formatter (improved code style, slightly different output so watch out it does not break the compatibility to your own scripts)

**Version 0.2.17** - Improving HumanReadable Formatter

**Version 0.2.18** - Fixing NEXT_HOP attribute output on JSON formatter

**Version 0.2.19** - Add BlackholeFilter to filter blackhole routes based on NEXT_HOP or RFC 7999 community

**Version 0.2.20** - Fixing bug output of large communities when using the LineBased formatter

**Version 0.2.20** - Add-Path capability added (RFC7911)