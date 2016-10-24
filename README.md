![GitHub Logo](https://cdn.rawgit.com/de-cix/pbgp-parser/master/logo_pbgpp.svg)

# PCAP BGP Parser (pbgpp)
DE-CIX developed a PCAP parser for analyzing BGP messages collected with tcpdump. The parser reads PCAP input from file system, stdin, or directly from network interface. Furthermore, the parser is able to use several output filters and pipes to tailor the output for your individual needs. Therefore, we decided to develop *PCAP BGP Parser* aka *pbgpp*. The filters and pipes can be easily extended - we are happy to include your extensions any time :)

## Why not Wireshark?
Wireshark is an awesome tool! Unfortunatly, it only offers an graphical interface that does not satisfy our requirements, e.g., existing BGP filters are limited to some fields. Also tshark as command line version of Wireshark was not able to output the parsed BGP messages in a toolchain-friendly way.

## Available inputs, formatters, and pipes
The parser is able to read PCAP from: File and standard input (stdin) - soon it will be able to read live packages directly from network interface.

The parser is able to format the parsed BGP messages into: a human-readable format that offers easy-to-read general information build for adhoc analysis of your network, JSON with full information scope, and a line based output. By using the line based output you may specify which fields you need to get displayed in a single line. Each field is separated using the TAB character (\t). Therefore, that kind of output is pretty easy to parse with other tools/scripts - you can easily integrate it into a toolchain.

Potential output targets are: stdout, file, and streams to Apache Kafka.

## Usage
First of all please make sure that your system meets the application requirements by using PyPA pip. Furthermore pbgpp requires Python 3.

    pip install -r requirements.txt

You may use `--help` argument to view all available options and arguments. The most simple usage example reads a PCAP file from standard in, produces a human readable output and pipes it back to standard out:

    cat /path/to/file.pcap | pbgpp.py -
    
Moreover, filtering is pretty straight forward: assuming you just want to display BGP UPDATE messages that are _only_ containing withdrawals just use the following command.

    cat /path/to/file.pcap | pbgpp.py --filter-message-type UPDATE --filter-message-subtype WITHDRAWAL -
    
To pipe your output directly into a file you can use the following command. Of course you are able to combine it with filters or different input methods, like reading from a PCAP file.

    cat /path/to/file.pcap | pbgpp.py -p FILE -o output.txt -

There are some remarks for the usage of *Apache Kafka* as output target. First of all use the `-p KAFKA` argument to set the output pipe. In addition, you must specify the target Apache Kafka server and topic. Port 9092 is the default and does not need to be specified.

    cat /path/to/file.pcap | pbgpp.py -p KAFKA --kafka-server 127.0.0.1 --kafka-topic pbgpp -f JSON -
    
Using `-f JSON` or `-f LINE` is highly recommended. The output will be encoded in UTF-8 and sent to your specified target server.

## Logging
pbgpp is producing logging output while parsing your PCAP input. The default option is `--quite` and needn't to be specified; it disables the whole logging output. Parsing output, which is piped to stdout, is **not** affected by this argument. By using the `--verbose` argument you switch to more verbosive output. Obviously, it can not be used in combination with the `--quiet` argument. By default pbgpp logs at log level INFO. To separate the log output from the parser output you are able to use stream redirection in \*nix operating systems.

    # This command will pipe parsing output to stdout and log output at DEBUG level to stderr
    cat /path/to/file.pcap | pbgpp.py -p STDOUT --verbose 2> /path/to/output.log
    
*Note*, if you are not using stream redirection in combination with verbosive or normal logging level you won't be able to separate parsing output from logging output.

## Limitations
Currently, the parser doesn't perform a reassembly on fragmented TCP packets. This may leads into parsing errors and application warnings when you are trying to parse large BGP packets with several messages.

## Contributions
Feel free to contribute your own extensions, enhancements, or even fixes. Check out the issues page on GitHub for further information.

If you have any other kind of inquiries feel free to contact our research and development team: rnd <>at<> de-cix <>dot<> net

## Copyright, License & Credits
PCAP BGP Parser (pbgpp) - Copyright (C) 2016, DE-CIX Management GmbH.

PCAP BGP Parser (pbgpp) is published under Apache License 2.0 (https://www.apache.org/licenses/LICENSE-2.0).

This product includes software developed by CORE Security Technologies (http://www.coresecurity.com/).
