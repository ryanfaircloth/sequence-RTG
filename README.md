sequence - Extensions built in this fork
========

**`sequence` was iced by the previous author but we have picked it up and added some extra functionality in and around the module. The original READ ME notes are still listed at the bottom of this page.
The original notes are still valid for this module as is the information on his website.**

Here we will detail the extensions made to Sequence so it can generate patterns in the format used by two of the leading log management systems log file parsers - Syslog-ng's patternDB and Logstash's Grok filter.

The goal of the extension was to be able to use the Sequence module to find the patterns but to be able to export the patterns in a format for the parsing functionality of other log management systems. 

For our purposes we focused mostly on Syslog-ng patternDB but have added the Grok filer for Logstash as we believe it will be applicable to a wider audience.
With that in mind, the Syslog-ng patternDB format has had a greater level of testing than the Grok patterns, so there is a possibility
that it may need a little bit of extra attention to be its best.

We also tried to preserve as much flexibility as possible with the ability to turn on and off the new features where sensible with command line flags or config settings.

One of the first additions was the ability to run the solution continuously with the addition of the database for storing the patterns and
keeping track of the match counts of each pattern. This allows the pattern reviewer to review patterns when convenient and 
also informs them of how frequently a pattern is matched to help prioritise their review and promotion. 

The database type that we have used is SQLite3 but we have tested the code with Microsoft SQL Server 2014, PostgresSQL,
MySql also. SQLite3 is supported by a `createdatabase` method from the commandline, for the other three, there is a 
script in the database_scripts folder. The ORM we have used in SQLBoiler and a README for changing the database type and regenerating the models
can be also found in the database_scripts folder.

Sequence can handle message input via either the standard input or a file. Using standard input with the batch size flag you can have
the solution running and reading in the data in real time, but waiting until the batch limit is reached to process the 
messages. Sequence needs a group of messages to find the patterns, it cannot work in an online mode where it can process messages
one by one. The batch limit only works with standard input currently, not with input from file.

Alternatively if you don't want to send the live stream of the data to the solution or process all of your log messages, you can select a subset of messages and 
send them through sequence via a file to output directly to another file to discover the patterns for that set. These can immediately be reviewed and 
promoted.  In this sense, it can be used to save you creating patterns by hand from a few examples. This is done by passing the --all flag with the analyzebyservice
method and the flags for exportpatterns along with the expected analyzebyservice flags. See the READ ME in the cmd/sequence_db folder for more information on the flags and their uses.

The original sequence did not handle multiline messages and we have added the functionality to make a pattern from the first line only and absorb the 
remainder of the message as one token. This seems to be enough for our purposes, but may not work for everyone.


For handling larger volumes of messages, we created an analyzebyservice method to do closely what the original analyze method does in the original sequence project,
but splits and analyses the messages by their source system. This allows processing of a wider range of patterns and prevents messages from
other services impacting the patterns.  

Every created pattern is given a patternID value that is combination of the pattern and the service name translated into
a sha 1 value. This is so that it is repeatable, if the database is lost or wiped for maintenance the same pattern and service 
will give the same id. Unfortunately however if the pattern changes due to a software update of either sequence or the 
source system, then a new id will be created. 

The patterns can be exported for either patterndb or grok format. PatternDB files have been tested in their entirety with patternDB,
the grok patterns have been tested individually with a grok pattern tester. Patterndb uses the idea of a combination of service and message to define its patterns,
but grok does not, so for grok you may find you get a duplication of patterns if two different services generate the same pattern.

As with any effort at translation, there are a few situations where it can lead to a translation that is not quite right. For SEQUENCE a pattern such as `%string% %string1%` would only match a two word string,
but with the patternDB translation `@ESTRING:string: @@ESTRING:string1:@` it would match any message with two words or more.
To help avoid exporting these patterns we introduced the idea of a complexity score. The scores range from 0 to 1, 0 being a pattern with no tokens and 1 being a pattern with all
string tokens. Around a complexity score of 0.5, most of the bad patterns are avoided. It is, however, not exact and there are a few with higher scores that are ok too.
The idea is to give the review some control over what is exported, and the (hopefully) the ability to focus on the best patterns first.


*NOTE: For the export to patterndb and grok, some of the regex values in the config file have not been completed, I have added them as I have needed them for the patterns
that we have found. Any date/time format that has no spaces is just a string variable, but the others need a regex to be matched properly.*


sequence - Read me from original author
========

**`sequence` is currently iced since I don't have time to continue, and should be considered unstable until further notice. If anyone's interested in continue development of this, I would be happy to add you to the project.**

[sequencer.io](http://sequencer.io)

[![GoDoc](http://godoc.org/github.com/surge/sequence?status.svg)](http://godoc.org/github.com/surge/sequence) 

[![GoDoc](http://godoc.org/github.com/surge/sequence/cmd/sequence?status.svg)](http://godoc.org/github.com/surge/sequence/cmd/sequence)


`sequence` is a _high performance sequential log scanner, analyzer and parser_. It _sequentially_ goes through a log message, _parses_ out the meaningful parts, without the use regular expressions. It can achieve _high performance_ parsing of **100,000 - 200,000 messages per second (MPS)** without the need to separate parsing rules by log source type.

### Motivation

Log messages are notoriously difficult to parse because they all have different formats. Industries (see Splunk, ArcSight, Tibco LogLogic, Sumo Logic, Logentries, Loggly, LogRhythm, etc etc etc) have been built to solve the problems of parsing, understanding and analyzing log messages.

Let's say you have a bunch of log files you like to parse. The first problem you will typically run into is you have no way of telling how many DIFFERENT types of messages there are, so you have no idea how much work there will be to develop rules to parse all the messages. Not only that, you have hundreds of thousands, if not  millions of messages, in front of you, and you have no idea what messages are worth parsing, and what's not.

The typical workflow is develop a set of regular expressions and keeps testing against the logs until some magical moment where all the logs you want parsed are parsed. Ask anyone who does this for a living and they will tell you this process is long, frustrating and error-prone.

Even after you have developed a set of regular expressions that match the original set of messages, if new messages come in, you will have to determine which of the new messages need to be parsed. And if you develop a new set of regular expressions to parse those new messages, you still have no idea if the regular expressions will conflict with the ones you wrote before. If you write your regex parsers too liberally, it can easily parse the wrong messages.

After all that, you will end up finding out the regex parsers are quite slow. It can typically parse several thousands messages per second. Given enough CPU resources on a large enough machine, regex parsers can probably parse tens of thousands of messages per second. Even to achieve this type of performance, you will likely need to limit the number of regular expressions the parser has. The more regex rules, the slower the parser will go.

To work around this performance issue, companies have tried to separate the regex rules for different log message types into different parsers. For example, they will have a parser for Cisco ASA logs, a parser for sshd logs, a parser for Apache logs, etc etc. And then they will require the users to tell them which parser to use (usually by indicating the log source type of the originating IP address or host.)

Sequence is developed to make analyzing and parsing log messages a lot easier and faster.

### Performance

The following performance benchmarks are run on a single 4-core (2.8Ghz i7) MacBook Pro, although the tests were only using 1 or 2 cores. The first file is a bunch of sshd logs, averaging 98 bytes per message. The second is a Cisco ASA log file, averaging 180 bytes per message. Last is a mix of ASA, sshd and sudo logs, averaging 136 bytes per message.

```
  $ ./sequence bench scan -i ../../data/sshd.all
  Scanned 212897 messages in 0.78 secs, ~ 272869.35 msgs/sec

  $ ./sequence bench parse -p ../../patterns/sshd.txt -i ../../data/sshd.all
  Parsed 212897 messages in 1.69 secs, ~ 126319.27 msgs/sec

  $ ./sequence bench parse -p ../../patterns/asa.txt -i ../../data/allasa.log
  Parsed 234815 messages in 2.89 secs, ~ 81323.41 msgs/sec

  $ ./sequence bench parse -d ../patterns -i ../data/asasshsudo.log
  Parsed 447745 messages in 4.47 secs, ~ 100159.65 msgs/sec
```

Performance can be improved by adding more cores:


```
  $ GOMAXPROCS=2 ./sequence bench scan -i ../../data/sshd.all -w 2
  Scanned 212897 messages in 0.43 secs, ~ 496961.52 msgs/sec

  GOMAXPROCS=2 ./sequence bench parse -p ../../patterns/sshd.txt -i ../../data/sshd.all -w 2
  Parsed 212897 messages in 1.00 secs, ~ 212711.83 msgs/sec

  $ GOMAXPROCS=2 ./sequence bench parse -p ../../patterns/asa.txt -i ../../data/allasa.log -w 2
  Parsed 234815 messages in 1.56 secs, ~ 150769.68 msgs/sec

  $ GOMAXPROCS=2 ./sequence bench parse -d ../patterns -i ../data/asasshsudo.log -w 2
  Parsed 447745 messages in 2.52 secs, ~ 177875.94 msgs/sec
```

### Limitations

* `sequence` does not handle multi-line logs. Each log message must appear as a single line. So if there's multi-line logs, they must first be converted into a single line.
* `sequence` has only been tested with a limited set of system (Linux, AIX, sudo, ssh, su, dhcp, etc etc), network (ASA, PIX, Neoteris, CheckPoint, Juniper Firewall) and infrastructure application (apache, bluecoat, etc) logs. If you have a set of logs you would like me to test out, please feel free to [open an issue](https://github.com/strace/sequence/issues) and we can arrange a way for me to download and test your logs.

### Usage

To run the unit tests, you need to be in the top level sequence dir:

```
go get github.com/strace/sequence
cd $GOPATH/src/github.com/strace/sequence
go test
```

To run the actual command you need to

```
cd $GOPATH/src/github.com/strace/sequence/cmd/sequence
go run sequence.go
```

Documentation is available at [sequencer.io](http://sequencer.io).

### License

Copyright (c) 2014 Dataence, LLC. All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
