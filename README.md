# PCAP BGP Parser (pbgpp)
DE-CIX developed a PCAP parser for analyzing BGP messages. The parser is able to read PCAP input from file system or stdin. Soon it will be able to read and parse BGP messages directly from network interface. Furthermore the parser is able to use several output formatters and pipes to modify the output for your individual needs. Those formatters and pipes can be easily extended - feel free to contribute them to our public repository.

## Why not Wireshark?
Wireshark is an awesome tool. But it just offers a graphical environment that does not fulify our use cases. Also tshark as command line version of Wireshark was not able to output the parsed BGP messages in a toolchain-friendly way. Therefore we decided to develop an own parsing tool that implements our special use cases.

## Available inputs, formatters and pipes
The parser is able to read PCAP from: File and standard input (stdin) - soon it will be able to read live packages directly from network interface.

The parser is able to format the parsed BGP messages into: a human-readable format that offers easy-to-read general information but not the whole insight, JSON with full information scope and a line based output. By using the line based output the user is able to specify which fields he wants to get displayed in a single line. Each field is separated using the TAB character (\t). Therefore that kind of output is pretty easy to parse - you can easily integrate it in a toolchain.

The parser is able to pipe its output to: standard out (stdout), a file and into an Apache Kafka topic.

## Contributions
Feel free to contribute your own extensions, enhancements or fixes for existing bugs. Check out the issues page in GitHub for further information.

If you have any other kind of enqueries feel free to contact our research and development team: rnd@de-cix.net

## Copyright, License & Credits
PCAP BGP Parser (pbgpp) - Copyright (C) 2016, DE-CIX Management GmbH.

PCAP BGP Parser (pbgpp) is published under Apache License 2.0 (https://www.apache.org/licenses/LICENSE-2.0).

This product includes software developed by CORE Security Technologies (http://www.coresecurity.com/).
