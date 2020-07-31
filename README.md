![pbgpp Logo](https://github.com/de-cix/pbgp-parser/blob/master/logo_pbgp.png)

# PCAP BGP Parser (pbgpp)
[![PyPI version](https://badge.fury.io/py/pbgpp.svg)](https://badge.fury.io/py/pbgpp)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](https://github.com/de-cix/pbgp-parser/blob/master/LICENSE.txt)

DE-CIX developed a PCAP parser to decode BGP messages collected with tcpdump. The parser reads PCAP input from file system, stdin, or by listening on a network interface. Furthermore, the parser is able to use several output filters and pipes to tailor the output for your individual needs. Therefore, we decided to develop *PCAP BGP Parser* aka *pbgpp*. The filters and pipes can be easily extended - we are happy to include your extensions any time :)

## Why not Wireshark?
Wireshark is an awesome tool! Unfortunately, it only offers an graphical interface that does not satisfy our requirements, e.g., existing BGP filters are limited to some fields. Also tshark as command line version of Wireshark was not able to output the parsed BGP messages in a toolchain-friendly way.

## Available inputs, formatters, and pipes
The parser is able to read PCAP from: File and standard input (stdin) - soon it will be able to read live packages directly from network interface.

The parser is able to format the parsed BGP messages into: a human-readable format that offers easy-to-read general information build for adhoc analysis of your network, JSON with full information scope, and a line based output. By using the line based output you may specify which fields you need to get displayed in a single line. Each field is separated using the TAB character (\t). Therefore, that kind of output is pretty easy to parse with other tools/scripts - you can easily integrate it into a toolchain. When you are not specifying any output fields using `--fields` the parser will use the following output pattern per default in `-f LINE`-Mode: Timestamp, Message Type, Message Subtype, Announced Prefixes, Withdrawn Prefixes

Potential output targets are: stdout, file, and streams to Apache Kafka.

## Usage
You are able to install pbgpp by using PyPI. To do so please make sure that you have installed the `libpcap-dev` packet for your operating system. Otherwise compiling pcapy will fail.

    sudo pip install pbgpp

You may use `--help` argument to view all available options and arguments. The most simple usage example reads a PCAP file from standard in, produces a human readable output and pipes it back to standard out:

    cat /path/to/file.pcap | pbgpp -
    
Sometimes you may want to process many PCAPs at once. The parser is supporting wildcards when using the `--pcap` argument (Make sure you are using the quotes!).

    pbgpp --pcap "/path/to/many/files/2017-02-01*.pcap" -f JSON
    
Moreover, filtering is pretty straight forward: assuming you just want to display BGP UPDATE messages that are _only_ containing withdrawals use the following command.

    cat /path/to/file.pcap | pbgpp --filter-message-type UPDATE --filter-message-subtype WITHDRAWAL -
    
To pipe your output directly into a file you can use the following command. Of course you are able to combine it with filters or different input methods, like reading from a PCAP file.

    cat /path/to/file.pcap | pbgpp -p FILE -o output.txt -

There are some remarks for the usage of *Apache Kafka* as output target. First of all use the `-p KAFKA` argument to set the output pipe. In addition, you must specify the target Apache Kafka server and topic. Port 9092 is the default and does not need to be specified.

    cat /path/to/file.pcap | pbgpp -p KAFKA --kafka-server 127.0.0.1 --kafka-topic pbgpp -f JSON -
    
Using `-f JSON` or `-f LINE` is highly recommended. The output will be encoded in UTF-8 and sent to your specified target server.

Finally, you can install the package as a system command-line tool by using setuptools:

    python setup.py install

This will install the `pbgpp` tool on your system path which is equivalent to `pbgpp.py` in this directory.

## Logging
pbgpp is producing logging output while parsing your PCAP input. The default option is `--quiet` and needn't to be specified; it disables the whole logging output. Parsing output, which is piped to stdout, is **not** affected by this argument. By using the `--verbose` argument you switch to more detailed output. Obviously, it can not be used in combination with the `--quiet` argument. By default, pbgpp logs at log level INFO. To separate the log output from the parser output you are able to use stream redirection in \*nix operating systems.

    # This command will pipe parsing output to stdout and log output at DEBUG level to stderr
    cat /path/to/file.pcap | pbgpp.py -p STDOUT --verbose 2> /path/to/output.log

**Note**, if you are not using stream redirection in combination with verbose or normal logging level you won't be able to separate parsing output from logging output.

## BGP Add-Path (RFC7911)
IETF introduced with RFC7911 the so called Add-Path feature. As mentioned in this RFC, a packet analyzer can not distinguish between a standard network prefix and a PathIdentifier.
Therefore we implemented the following feature. A user is now able to toggle a Flag which allows three different interpretation modes of the NLRI fields.

    #Use the flag like this: `--add-path-metric [0|1|2]`
    pbgpp.py  --pcap my.pcap --add-path-metric 2

0 (default): Assume that there are **no** Add-Path messages 

1: Assume that there are **only** Add-Path messages

2: Use the implemented metric. 
If the NLRI field contains two 0-Bytes (translated to two 0.0.0.0/0 prefixes which should not occur at all) the programm assumes that the first 4 bytes are a Path Identifier and treates this field as an Add-Path message.  

## Limitations
Currently, the parser doesn't perform a reassembly on fragmented TCP packets. This may leads into parsing errors and application warnings when you are trying to parse large BGP packets with several messages.

Currently, we are looking into some problems with running pbgpp with Python 2.7 and streaming the output to Kafka. However, Python 3.x works just fine.

## Contributions
Feel free to contribute your own extensions, enhancements, or even fixes. Check out the issues page on GitHub for further information.

If you have any other kind of inquiries feel free to contact our research and development team: rnd <>at<> de-cix <>dot<> net

## Copyright, License & Credits
PCAP BGP Parser (pbgpp) - Copyright (C) 2016, DE-CIX Management GmbH.

PCAP BGP Parser (pbgpp) is published under Apache License 2.0 (https://www.apache.org/licenses/LICENSE-2.0).

This product includes software developed by CORE Security Technologies (http://www.coresecurity.com/).
*
