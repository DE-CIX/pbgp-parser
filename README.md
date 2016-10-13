# PCAP BGP Parser (pbgpp)
DE-CIX developed a PCAP parser for analyzing BGP messages collected with tcpdump. The parser reads PCAP input from file system, stdin, or directly from network interface. Furthermore, the parser is able to use several output filters and pipes to tailor the output for your individual needs. Therefore, we decided to develop *PCAP BGP Parser* aka *pbgpp*. The filters and pipes can be easily extended - we are happy to include your extensions any time :)

## Why not Wireshark?
Wireshark is an awesome tool! Unfortunalty, it only offers an graphical interface that does not satisfy our requirements, e.g., existing BGP fitlers are limited to some fields. Also tshark as command line version of Wireshark was not able to output the parsed BGP messages in a toolchain-friendly way.

## Available inputs, formatters, and pipes
The parser is able to read PCAP from: File and standard input (stdin) - soon it will be able to read live packages directly from network interface.

The parser is able to format the parsed BGP messages into: a human-readable format that offers easy-to-read general information build for adhoc analysis of your network, JSON with full information scope, and a line based output. By using the line based output you may specify which fields you need to get displayed in a single line. Each field is separated using the TAB character (\t). Therefore, that kind of output is pretty easy to parse with other tools/scripts - you can easily integrate it into a toolchain.

Potential output targets are: stdout, file, and streams to Apache Kafka.

## Usage
You may use `--help` argument to view all available options and arguments. The most simple usage example reads a PCAP file from standard in, produces a human readable output and pipes it back to standard out:

    cat /path/to/file.pcap | pbgpp.py -
    
Moreover, filtering is pretty straight forward: assuming you just want to display BGP UPDATE messages that are _only_ containing withdrawals just use the following command.

    cat /path/to/file.pcap | pbgpp.py --filter-message-type UPDATE --filter-message-subtype WITHDRAWAL -

## Contributions
Feel free to contribute your own extensions, enhancements, or even fixes. Check out the issues page in GitHub for further information.

If you have any other kind of enqueries feel free to contact our research and development team: rnd@de-cix.net

## Copyright, License & Credits
PCAP BGP Parser (pbgpp) - Copyright (C) 2016, DE-CIX Management GmbH.

PCAP BGP Parser (pbgpp) is published under Apache License 2.0 (https://www.apache.org/licenses/LICENSE-2.0).

This product includes software developed by CORE Security Technologies (http://www.coresecurity.com/).
