// Copyright (c) 2014 Dataence, LLC. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package sequence

import (
	"github.com/stretchr/testify/require"
	"testing"
)

var (
	parsetests = []struct {
		format, msg, rule string
		pos               []int
	}{
		{
			"general",
			"id=firewall time=\"2005-03-18 14:01:46\" fw=TOPSEC priv=6 recorder=kernel type=conn policy=414 proto=TCP rule=accept src=61.167.71.244 sport=35223 dst=210.82.119.211 dport=25 duration=27 inpkt=37 outpkt=39 sent=1770 rcvd=20926 smac=00:04:c1:8b:d8:82 dmac=00:0b:5f:b2:1d:80",
			"id = %appname% time = \" %regextime:4% \" fw = %apphost% priv = %integer% recorder = %string% type = %string% policy = %policyid% proto = %protocol% rule = %status% src = %srcip% sport = %srcport% dst = %dstip% dport = %dstport% duration = %integer% inpkt = %pktsrecv% outpkt = %pktssent% sent = %bytessent% rcvd = %bytesrecv% smac = %srcmac% dmac = %dstmac%",
			[]int{5, 25, 41},
		},
		{
			"general",
			"may  5 18:07:27 dlfssrv unix: dlfs_remove(), entered fname=tempfile",
			"%regextime:1% %apphost% %appname% : %method% ( ) , %string% fname = %string%",
			[]int{0, 14, 24, 36, 51, 67},
		},
		{
			"general",
			"may  2 15:51:24 dlfssrv unix: vfs root entry",
			"%regextime:1% %apphost% %appname% : vfs root %action%",
			[]int{0, 14, 24, 45},
		},
		{
			"general",
			"jan 15 14:07:04 testserver sudo: pam_unix(sudo:auth): conversation failed",
			"%regextime:1% %apphost% %appname% : %method% ( %string% : %action% ) : conversation %status%",
			[]int{0, 14, 24, 36},
		},
		{
			"general",
			"jan 15 14:07:04 testserver sudo: pam_unix(sudo:auth): password failed",
			"%regextime:1% %apphost% %appname% : %method% ( %string% : %action% ) : %string% %status%",
			[]int{0, 14, 24, 36},
		},
		{
			"general",
			"jan 15 14:07:35 testserver passwd: pam_unix(passwd:chauthtok): password changed for ustream",
			"%regextime:1% %apphost% %appname% : %method% ( %string% : %action% ) : password changed for %dstuser%",
			[]int{0, 14, 24, 36},
		},
		{
			"general",
			"jan 15 19:15:55 jlz sshd[7106]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=188.65.16.110",
			"%regextime:1% %apphost% %appname% [ %sessionid% ] : %string% ( sshd : %string% ) : authentication %status% ; logname = %string% = %integer% euid = %integer% tty = %string% ruser = rhost = %srcip%",
			[]int{0, 14, 24, 36},
		},
		{
			"general",
			"jan 15 19:25:56 jlz sshd[7774]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=stat.atomsib.net ",
			"%regextime:1% %apphost% %appname% [ %sessionid% ] : %string% ( sshd : %string% ) : authentication %status% ; logname = %string% = %integer% euid = %integer% tty = %string% ruser = rhost = %srchost%",
			[]int{0, 14, 24, 36},
		},
		{
			"general",
			"Jan 12 10:38:51 irc sshd[7705]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=114.80.226.94  user=root",
			"%regextime:1% %apphost% %appname% [ %sessionid% ] : %string% ( sshd : %string% ) : authentication %status% ; logname = %string% = %integer% euid = %integer% tty = %string% ruser = rhost = %srcip% user = %dstuser%",
			[]int{0, 14, 24, 36},
		},
		{
			"general",
			"Jan 31 21:42:59 mail postfix/anvil[14606]: statistics: max connection rate 1/60s for (smtp:5.5.5.5) at Jan 31 21:39:37",
			"%regextime:1% %apphost% %string% [ %integer% ] : statistics : max connection rate %string% for ( smtp : %appip% ) at %time%",
			[]int{0, 14, 24, 36},
		},
		{
			"general",
			"Jan 31 21:42:59 mail postfix/anvil[14606]: statistics: max connection count 1 for (smtp:5.5.5.5) at Jan 31 21:39:37",
			"%regextime:1% %apphost% %string% [ %integer% ] : statistics : max connection count %integer% for ( smtp : %appip% ) at %time%",
			[]int{0, 14, 24, 36},
		},
		{
			"general",
			"Jan 31 21:42:59 mail postfix/anvil[14606]: statistics: max cache size 1 at Jan 31 21:39:37",
			"%regextime:1% %apphost% %string% [ %sessionid% ] : statistics : max cache size %integer% at %time%",
			[]int{0, 14, 24, 35},
		},
		{
			"general",
			"Jan 31 21:42:59 mail postfix/anvil[14606.4]: statistics: max cache size 1 at Jan 31 21:39:37",
			"%regextime:1% %apphost% %string% [ %sessionid:float% ] : statistics : max cache size %integer% at %time%",
			[]int{0, 14, 24, 35},
		},
		{
			"general",
			"Feb 06 13:37:00 box sshd[4388]: Accepted publickey for cryptix from dead:beef:1234:5678:223:32ff:feb1:2e50 port 58251 ssh2: RSA de:ad:be:ef:74:a6:bb:45:45:52:71:de:b2:12:34:56",
			"%regextime:1% %apphost% %appname% [ %sessionid% ] : Accepted publickey for %dstuser% from %srcip:ipv6% port %integer% ssh2 : RSA %string%",
			[]int{0, 14, 24, 36, 75, 90, 108, 129},
		},
		{
			"general",
			"Feb 06 13:37:00 box sshd[4388]: Accepted publickey for cryptix from 192.168.1.1 port 58251 ssh2: RSA de:ad:be:ef:74:a6:bb:45:45:52:71:de:b2:12:34:56",
			"%regextime:1% %apphost% %appname% [ %sessionid% ] : Accepted publickey for %dstuser% from %srcip% port %integer% ssh2 : RSA %string%",
			[]int{0, 14, 24, 36},
		},
		// relates to #7
		{
			"general",
			"Feb  8 12:15:52 mail postfix/pipe[76139]: 499F62D65: to=<userA@company.office>, orig_to=<alias24@alias.com>, relay=dovecot, delay=0.24, delays=0.21/0/0/0.04, dsn=2.0.0, status=sent (delivered via dovecot service)",
			"%regextime:1% %apphost% %string% [ %sessionid% ] : %msgid% : to = < %srcemail% > , orig_to = < %string% > , relay = %string% , delay = %float% , delays = %string% , dsn = %string% , status = %status% ( %reason::*% )",
			[]int{0, 14, 24, 35, 51, 68, 95, 202},
		},
		{
			"general",
			"Feb  8 21:51:10 mail postfix/pipe[84059]: 440682230: to=<userB@company.office>, orig_to=<userB@company.biz>, relay=dovecot, delay=0.9, delays=0.87/0/0/0.03, dsn=2.0.0, status=sent (delivered via dovecot service)",
			"%regextime:1% %apphost% %string% [ %sessionid% ] : %msgid:integer% : to = < %srcemail% > , orig_to = < %string% > , relay = %string% , delay = %float% , delays = %string% , dsn = %string% , status = %status% ( %reason::+% )",
			[]int{0, 14, 24, 35, 51, 210},
		},
		{
			"general",
			"Feb  8 21:51:10 mail postfix/pipe[84059]: 440682230: to=<userB@company.office>, orig_to=<userB@company.biz>, relay=dovecot, delay=1, delays=0.87/0/0/0.03, dsn=2.0.0, status=sent (delivered via dovecot service)",
			"%regextime:1% %apphost% %string% [ %sessionid% ] : %msgid:integer% : to = < %srcemail% > , orig_to = < %string% > , relay = %string% , delay = %integer% , delays = %string% , dsn = %string% , status = %status% ( %reason::+% )",
			[]int{0, 14, 24, 35, 51, 212},
		},
		{
			"general",
			"jan 14 10:15:56 testserver sudo:    gonner : tty=pts/3 ; pwd=/home/gonner ; user=root ; command=/bin/su - ustream",
			"%regextime:1% %apphost% %appname% : %srcuser% : tty = %string% ; pwd = %string% ; user = %dstuser% ; command = %string% - ustream",
			[]int{0, 14, 24, 36},
		},
		//comment these tests for now, need to debug why they are no longer the same patterns
		/*{
			"general",
			"2015-02-11 11:04:40 H=(amoricanexpress.com) [64.20.195.132]:10246 F=<fxC4480@amoricanexpress.com> rejected RCPT <SCRUBBED@SCRUBBED.com>: Sender verify failed",
			"%msgtime% h = ( %srchost% ) [ %srcip% ] : %srcport% f = < %srcemail% > %action% rcpt < %dstemail% > : %reason::-%",
		},
		{
			"general",
			`2015-01-24T19:34:47.269-0500 [conn72800] query foo.bar query: { _id: { $gte: { ContactId: BinData(3, 6C764EA2DABCE241C3E) }, $lt: { ContactId: BinData(3, 6C764EA2DAB4D9B1C3F) } } } planSummary: IXSCAN { _id: 1 } ntoreturn:0 ntoskip:0 nscanned:12 nscannedObjects:12 keyUpdates:0 numYields:10 locks(micros) r:2733 nreturned:12 reslen:4726 102ms`,
			`%msgtime% [ %sessionid:string% ] %action% %string% query : %object:-:plansummary% plansummary : %object::-%`,
		},
		{
			"general",
			`2015-01-24T22:14:02.106-0500 [conn73988] update foo.bar query: { _id: BinData(3, 0294D28B65F8EA45B6E63E5F), Identifiers.Identifier: /^john\\smith@gmail\.com$/i, Lease: null } update: { $set: { Lease: { ExpirationTime: new Date(1422155662305), Owner: { Identifier: "47eb3bdd-2d18-4a02-8d95-b5036d6", Type: 1 } } } } nMatched:1 nModified:1 keyUpdates:0 numYields:0 locks(micros) w:292 365ms`,
			`%msgtime% [ %sessionid:string% ] %action% %string% query : %object:-:update% update : %object:-:nmatched% %string:-%`,
		},
		{
			"json",
			`{"reference":"","roundTripDuration":206}`,
			"roundtripduration = %duration%",
		},
		{
			"json",
			`{"EventTime":"2014-08-16T12:45:03-0400","URI":"myuri","uri_payload":{"value":[{"open":"2014-08-16T13:00:00.000+0000","close":"2014-08-16T23:00:00.000+0000","isOpen":true,"date":"2014-08-16"}],"Count":1}}`,
			"eventtime = %msgtime% uri = %object% uri_payload.value.0.open = %time% uri_payload.value.0.close = %time% uri_payload.value.0.isopen = %string% uri_payload.value.0.date = %time% uri_payload.count = %integer%",
		},*/
	}

	parsetestsnosp = []struct {
		format, msg, rule string
		pos               []int
	}{
		{
			"general",
			"id=firewall time=\"2005-03-18 14:01:46\" fw=TOPSEC priv=6 recorder=kernel type=conn policy=414 proto=TCP rule=accept src=61.167.71.244 sport=35223 dst=210.82.119.211 dport=25 duration=27 inpkt=37 outpkt=39 sent=1770 rcvd=20926 smac=00:04:c1:8b:d8:82 dmac=00:0b:5f:b2:1d:80",
			"id=%appname% time=\"%msgtime%\" fw=%apphost% priv=%integer% recorder=%string% type=%string% policy=%policyid% proto=%protocol% rule=%status% src=%srcip% sport=%srcport% dst=%dstip% dport=%dstport% duration=%integer% inpkt=%pktsrecv% outpkt=%pktssent% sent=%bytessent% rcvd=%bytesrecv% smac=%srcmac% dmac=%dstmac%",
			[]int{3, 19, 33, 48},
		},
		{
			"general",
			"may  5 18:07:27 dlfssrv unix: dlfs_remove(), entered fname=tempfile",
			"%regextime:1% %apphost% %appname%: %method%(), entered fname=%string%",
			[]int{0, 14, 24, 35, 61},
		},
		{
			"general",
			"may  2 15:51:24 dlfssrv unix: vfs root entry",
			"%msgtime% %apphost% %appname%: vfs root %action%",
			[]int{0, 10, 20, 29},
		},
		{
			"general",
			"jan 15 14:07:04 testserver sudo: pam_unix(sudo:auth): conversation failed",
			"%msgtime% %apphost% %appname%: %method%( %string% : %action% ) : conversation %status%",
			[]int{0, 10, 20, 29},
		},
		{
			"general",
			"jan 15 14:07:04 testserver sudo: pam_unix(sudo:auth): password failed",
			"%msgtime% %apphost% %appname%: %method%( %string% : %action% ) : %string% %status%",
			[]int{0, 10, 20, 29},
		},
		{
			"general",
			"jan 15 14:07:35 testserver passwd: pam_unix(passwd:chauthtok): password changed for ustream",
			"%msgtime% %apphost% %appname%: %method%( %string% : %action% ) : password changed for %dstuser%",
			[]int{0, 10, 20, 29},
		},
		{
			"general",
			"jan 15 19:15:55 jlz sshd[7106]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=188.65.16.110",
			"%msgtime% %apphost% %appname%[%sessionid%]: %string%(sshd:%string%): authentication %status%; logname= %string%=%integer% euid=%integer% tty=%string% ruser= rhost=%srcip%",
			[]int{0, 10, 20, 29},
		},
		{
			"general",
			"jan 15 19:25:56 jlz sshd[7774]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=stat.atomsib.net ",
			"%msgtime% %apphost% %appname%[%sessionid%]: %string%(sshd:%string%): authentication %status%; logname= %string%=%integer% euid=%integer% tty=%string% ruser= rhost=%srchost%",
			[]int{0, 10, 20, 29},
		},
		{
			"general",
			"Jan 12 10:38:51 irc sshd[7705]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=114.80.226.94  user=root",
			"%msgtime% %apphost% %appname%[%sessionid%]: %string%(sshd:%string%): authentication %status%; logname= %string%=%integer% euid=%integer% tty=%string% ruser= rhost=%srcip% user=%dstuser%",
			[]int{0, 10, 20, 29},
		},
		{
			"general",
			"Jan 31 21:42:59 mail postfix/anvil[14606]: statistics: max connection rate 1/60s for (smtp:5.5.5.5) at Jan 31 21:39:37",
			"%msgtime% %apphost% %string%[%integer%]: statistics: max connection rate %string% for (smtp:%appip%) at %time%",
			[]int{0, 10, 20, 29},
		},
		{
			"general",
			"Jan 31 21:42:59 mail postfix/anvil[14606]: statistics: max connection count 1 for (smtp:5.5.5.5) at Jan 31 21:39:37",
			"%msgtime% %apphost% %string%[%integer%]: statistics: max connection count %integer% for (smtp:%appip%) at %time%",
			[]int{0, 10, 20, 29},
		},
		{
			"general",
			"Jan 31 21:42:59 mail postfix/anvil[14606]: statistics: max cache size 1 at Jan 31 21:39:37",
			"%msgtime% %apphost% %string%[%sessionid%]: statistics: max cache size %integer% at %time%",
			[]int{0, 10, 20, 29},
		},
		{
			"general",
			"Jan 31 21:42:59 mail postfix/anvil[14606.4]: statistics: max cache size 1 at Jan 31 21:39:37",
			"%msgtime% %apphost% %string%[%sessionid:float%]: statistics: max cache size %integer% at %time%",
			[]int{0, 10, 20, 29, 76, 89},
		},
		{
			"general",
			"Feb 06 13:37:00 box sshd[4388]: Accepted publickey for cryptix from dead:beef:1234:5678:223:32ff:feb1:2e50 port 58251 ssh2: RSA de:ad:be:ef:74:a6:bb:45:45:52:71:de:b2:12:34:56",
			"%msgtime% %apphost% %appname%[%sessionid%]: Accepted publickey for %dstuser% from %srcip:ipv6% port %integer% ssh2: RSA %string%",
			[]int{0, 10, 20, 30, 67, 82},
		},
		{
			"general",
			"Feb 06 13:37:00 box sshd[4388]: Accepted publickey for cryptix from 192.168.1.1 port 58251 ssh2: RSA de:ad:be:ef:74:a6:bb:45:45:52:71:de:b2:12:34:56",
			"%msgtime% %apphost% %appname%[%sessionid%]: Accepted publickey for %dstuser% from %srcip% port %integer% ssh2: RSA %string%",
			[]int{0, 10, 20, 30, 67, 82},
		},
		// relates to #7
		{
			"general",
			"Feb  8 12:15:52 mail postfix/pipe[76139]: 499F62D65: to=<userA@company.office>, orig_to=<alias24@alias.com>, relay=dovecot, delay=0.24, delays=0.21/0/0/0.04, dsn=2.0.0, status=sent (delivered via dovecot service)",
			"%msgtime% %apphost% %string%[%sessionid%]: %msgid%: to=<%srcemail%>, orig_to=<%string%>, relay=%string%, delay=%float%, delays=%string%, dsn=%string%, status=%status% (%reason::*%)",
			[]int{0, 10, 20, 29, 43, 56, 78, 95, 111, 127, 141, 158, 168},
		},
		{
			"general",
			"Feb  8 21:51:10 mail postfix/pipe[84059]: 440682230: to=<userB@company.office>, orig_to=<userB@company.biz>, relay=dovecot, delay=0.9, delays=0.87/0/0/0.03, dsn=2.0.0, status=sent (delivered via dovecot service)",
			"%msgtime% %apphost% %string%[%sessionid%]: %msgid:integer%: to=<%srcemail%>, orig_to=<%string%>, relay=%string%, delay=%float%, delays=%string%, dsn=%string%, status=%status% (%reason::+%)",
			[]int{0, 10, 20, 29, 43, 64, 86, 103, 119, 135, 149, 166, 176},
		},
		{
			"general",
			"Feb  8 21:51:10 mail postfix/pipe[84059]: 440682230: to=<userB@company.office>, orig_to=<userB@company.biz>, relay=dovecot, delay=1, delays=0.87/0/0/0.03, dsn=2.0.0, status=sent (delivered via dovecot service)",
			"%msgtime% %apphost% %string%[%sessionid%]: %msgid:integer%: to=<%srcemail%>, orig_to=<%string%>, relay=%string%, delay=%integer%, delays=%string%, dsn=%string%, status=%status% (%reason::+%)",
			[]int{0, 10, 20, 29, 43, 64, 86, 103, 119, 137, 151, 168, 178},
		},
		{
			"general",
			"jan 14 10:15:56 testserver sudo:    gonner : tty=pts/3 ; pwd=/home/gonner ; user=root ; command=/bin/su - ustream",
			"%msgtime% %apphost% %appname%: %srcuser% : tty=%string% ; pwd=%string% ; user=%dstuser% ; command=%string% - ustream",
			[]int{0, 10, 20, 31},
		},
		//comment these tests for now, need to debug why they are no longer the same patterns
		/*{
			"general",
			"2015-02-11 11:04:40 H=(amoricanexpress.com) [64.20.195.132]:10246 F=<fxC4480@amoricanexpress.com> rejected RCPT <SCRUBBED@SCRUBBED.com>: Sender verify failed",
			"%msgtime% h = ( %srchost% ) [ %srcip% ] : %srcport% f = < %srcemail% > %action% rcpt < %dstemail% > : %reason::-%",
		},
		{
			"general",
			`2015-01-24T19:34:47.269-0500 [conn72800] query foo.bar query: { _id: { $gte: { ContactId: BinData(3, 6C764EA2DABCE241C3E) }, $lt: { ContactId: BinData(3, 6C764EA2DAB4D9B1C3F) } } } planSummary: IXSCAN { _id: 1 } ntoreturn:0 ntoskip:0 nscanned:12 nscannedObjects:12 keyUpdates:0 numYields:10 locks(micros) r:2733 nreturned:12 reslen:4726 102ms`,
			`%msgtime% [ %sessionid:string% ] %action% %string% query : %object:-:plansummary% plansummary : %object::-%`,
		},
		{
			"general",
			`2015-01-24T22:14:02.106-0500 [conn73988] update foo.bar query: { _id: BinData(3, 0294D28B65F8EA45B6E63E5F), Identifiers.Identifier: /^john\\smith@gmail\.com$/i, Lease: null } update: { $set: { Lease: { ExpirationTime: new Date(1422155662305), Owner: { Identifier: "47eb3bdd-2d18-4a02-8d95-b5036d6", Type: 1 } } } } nMatched:1 nModified:1 keyUpdates:0 numYields:0 locks(micros) w:292 365ms`,
			`%msgtime% [ %sessionid:string% ] %action% %string% query : %object:-:update% update : %object:-:nmatched% %string:-%`,
		},
		{
			"json",
			`{"reference":"","roundTripDuration":206}`,
			"roundtripduration = %duration%",
		},
		{
			"json",
			`{"EventTime":"2014-08-16T12:45:03-0400","URI":"myuri","uri_payload":{"value":[{"open":"2014-08-16T13:00:00.000+0000","close":"2014-08-16T23:00:00.000+0000","isOpen":true,"date":"2014-08-16"}],"Count":1}}`,
			"eventtime = %msgtime% uri = %object% uri_payload.value.0.open = %time% uri_payload.value.0.close = %time% uri_payload.value.0.isopen = %string% uri_payload.value.0.date = %time% uri_payload.count = %integer%",
		},*/
	}

	parsetests2 = []struct {
		format, msg, rule string
		pos               []int
	}{
		// relates to #5
		{
			"general",
			"Feb  8 12:15:52 mail postfix/pipe[76139]: 499F62D65: to=<userA@company.office>, orig_to=<alias24@alias.com>, relay=dovecot, delay=0.24, delays=0.21/0/0/0.04, dsn=2.0.0, status=sent ()",
			"%regextime:1% %apphost% %string% [ %sessionid% ] : %msgid% : to = < %srcemail% > , orig_to = < %string% > , relay = %string% , delay = %float% , delays = %string% , dsn = %string% , status = %status% ( %reason::*% )",
			[]int{0, 14, 24, 35, 51, 68, 95, 202},
		},
		{
			"general",
			"may  5 18:07:27 dlfssrv unix: dlfs_remove(), entered fname=tempfile",
			"%regextime:1% %apphost% %appname% : %method% ( ) , %string% fname = %object:string:*%",
			[]int{0, 14, 24, 36, 51, 68},
		},
		{
			"general",
			"may  5 18:07:27 dlfssrv unix: dlfs_remove(), entered fname=tempfile",
			"%regextime:1% %apphost% %appname% : %method% ( ) , %string% fname = %object:string:+%",
			[]int{0, 14, 24, 36, 51, 68},
		},
		{
			"general",
			"may  5 18:07:27 dlfssrv unix: dlfs_remove(), entered fname=tempfile - abc",
			"%regextime:1% %apphost% %appname% : %method% ( ) , %string% fname = %object:string:+%",
			[]int{0, 14, 24, 36, 51, 68},
		},
		{
			"general",
			"may  5 18:07:27 dlfssrv unix: dlfs_remove(), entered fname=tempfile - abc",
			"%regextime:1% %apphost% %appname% : %method% ( ) , %string% fname = %object:string:-%",
			[]int{0, 14, 24, 36, 51, 68},
		},
		{
			"general",
			"may  5 18:07:27 dlfssrv unix: dlfs_remove(), entered fname=",
			"%regextime:1% %apphost% %appname% : %method% ( ) , %string% fname = %object:string:*%",
			[]int{0, 14, 24, 36, 51, 68},
		},
		{
			"general",
			"id=firewall time=\"2005-03-18 14:01:46\" fw=TOPSEC priv= recorder=kernel type=conn policy=414 proto=TCP rule=accept src=61.167.71.244 sport=35223 dst=210.82.119.211 dport=25 duration=27 inpkt=37 outpkt=39 sent=1770 rcvd=20926 smac=00:04:c1:8b:d8:82 dmac=00:0b:5f:b2:1d:80",
			"id = %appname% time = \" %regextime:4% \" fw = %apphost% priv = %integer:*% recorder = %string% type = %string% policy = %policyid% proto = %protocol% rule = %status% src = %srcip% sport = %srcport% dst = %dstip% dport = %dstport% duration = %integer% inpkt = %pktsrecv% outpkt = %pktssent% sent = %bytessent% rcvd = %bytesrecv% smac = %srcmac% dmac = %dstmac%",
			[]int{5, 24, 45, 62},
		},
		{
			"general",
			"id=firewall time=\"2005-03-18 14:01:46\" fw=TOPSEC priv=6 recorder=kernel type=conn policy=414 proto=TCP rule=accept src=61.167.71.244 sport=35223 dst=210.82.119.211 dport=25 duration=27 inpkt=37 outpkt=39 sent=1770 rcvd=20926 smac=00:04:c1:8b:d8:82 dmac=00:0b:5f:b2:1d:80",
			"id = %appname% time = \" %regextime:4% \" fw = %apphost% priv = %integer:*% recorder = %string% type = %string% policy = %policyid% proto = %protocol% rule = %status% src = %srcip% sport = %srcport% dst = %dstip% dport = %dstport% duration = %integer% inpkt = %pktsrecv% outpkt = %pktssent% sent = %bytessent% rcvd = %bytesrecv% smac = %srcmac% dmac = %dstmac%",
			[]int{5, 24, 45, 62},
		},
		{
			"general",
			"jan 15 14:07:04 testserver : pam_unix(sudo:auth): password failed",
			"%regextime:1% %apphost% %appname:*% : %method% ( %string% : %action% ) : %string% %status%",
			[]int{0, 14, 24, 36},
		},
		{
			"general",
			"jan 15 14:07:04 testserver sudo: pam_unix(sudo:auth): password",
			"%regextime:1% %apphost% %appname% : %method% ( %string% : %action% ) : %string:*% %status%",
			[]int{0, 14, 24, 36, 47, 58, 71},
		},
		{
			"general",
			"jan 15 14:07:04 testserver sudo: pam_unix(sudo:auth): password failed",
			"%regextime:1% %apphost% %appname% : %method:+% ( %string% : %action% ) : %string% %status%",
			[]int{0, 14, 24, 36, 49, 60, 73, 82},
		},
		{
			"general",
			"jan 14 10:15:56 testserver sudo:    gonner : tty=pts/3 ; pwd=/home/gonner ; user=root ; command=/bin/su - ustream",
			"%regextime:1% %apphost% %appname% : %srcuser% : tty = %string% ; pwd = %string% ; user = %dstuser% ; command = %string% - ustream",
			[]int{0, 14, 24, 36, 52, 67, 83, 102},
		},
	}
	parsetests2nosp = []struct {
		format, msg, rule string
		pos               []int
	}{
		// relates to #5
		{
			"general",
			"Feb  8 12:15:52 mail postfix/pipe[76139]: 499F62D65: to=<userA@company.office>, orig_to=<alias24@alias.com>, relay=dovecot, delay=0.24, delays=0.21/0/0/0.04, dsn=2.0.0, status=sent ()",
			"%regextime:1% %apphost% %string%[%sessionid%]: %msgid%: to =<%srcemail%>, orig_to=<%string%>, relay=%string%, delay=%float%, delays=%string%, dsn=%string%, status=%status% ()",
			[]int{0, 14, 24, 33, 47, 60, 82, 99, 115, 131, 145, 162, 172},
		},
		{
			"general",
			"may  5 18:07:27 dlfssrv unix: dlfs_remove(), entered fname=tempfile",
			"%regextime:1% %apphost% %appname%: %method%(), %string% fname=%object:string:*%",
			[]int{0, 14, 24, 35, 47, 62},
		},
		{
			"general",
			"may  5 18:07:27 dlfssrv unix: dlfs_remove(), entered fname=tempfile",
			"%regextime:1% %apphost% %appname%: %method%(), %string% fname=%object:string:+%",
			[]int{0, 14, 24, 35, 47, 62},
		},
		{
			"general",
			"may  5 18:07:27 dlfssrv unix: dlfs_remove(), entered fname=tempfile - abc",
			"%regextime:1% %apphost% %appname%: %method%(), %string% fname=%object:string:+%",
			[]int{0, 14, 24, 35, 47, 62},
		},
		{
			"general",
			"may  5 18:07:27 dlfssrv unix: dlfs_remove(), entered fname=tempfile - abc",
			"%regextime:1% %apphost% %appname%: %method%(), %string% fname=%object:string:-%",
			[]int{0, 14, 24, 35, 47, 62},
		},
		{
			"general",
			"may  5 18:07:27 dlfssrv unix: dlfs_remove(), entered fname=",
			"%regextime:1% %apphost% %appname%: %method%(), %string% fname=%object:string:*%",
			[]int{0, 14, 24, 35, 47, 62},
		},
		{
			"general",
			"id=firewall time=\"2005-03-18 14:01:46\" fw=TOPSEC priv= recorder=kernel type=conn policy=414 proto=TCP rule=accept src=61.167.71.244 sport=35223 dst=210.82.119.211 dport=25 duration=27 inpkt=37 outpkt=39 sent=1770 rcvd=20926 smac=00:04:c1:8b:d8:82 dmac=00:0b:5f:b2:1d:80",
			"id=%appname% time=\"%regextime:4%\" fw=%apphost% priv=%integer:*% recorder=%string% type=%string% policy=%policyid% proto=%protocol% rule=%status% src=%srcip% sport=%srcport% dst=%dstip% dport=%dstport% duration=%integer% inpkt=%pktsrecv% outpkt=%pktssent% sent=%bytessent% rcvd=%bytesrecv% smac=%srcmac% dmac=%dstmac%",
			[]int{3, 19, 37, 52, 73, 87, 103, 120, 136, 149, 163, 177, 191, 210, 226, 244, 260, 277, 294, 308},
		},
		{
			"general",
			"id=firewall time=\"2005-03-18 14:01:46\" fw=TOPSEC priv=6 recorder=kernel type=conn policy=414 proto=TCP rule=accept src=61.167.71.244 sport=35223 dst=210.82.119.211 dport=25 duration=27 inpkt=37 outpkt=39 sent=1770 rcvd=20926 smac=00:04:c1:8b:d8:82 dmac=00:0b:5f:b2:1d:80",
			"id=%appname% time=\"%regextime:4%\" fw=%apphost% priv=%integer:*% recorder=%string% type=%string% policy=%policyid% proto=%protocol% rule=%status% src=%srcip% sport=%srcport% dst=%dstip% dport=%dstport% duration=%integer% inpkt=%pktsrecv% outpkt=%pktssent% sent=%bytessent% rcvd=%bytesrecv% smac=%srcmac% dmac=%dstmac%",
			[]int{3, 19, 37, 52, 73, 87, 103, 120, 136, 149, 163, 177, 191, 210, 226, 244, 260, 277, 294, 308},
		},
		{
			"general",
			"jan 15 14:07:04 testserver : pam_unix(sudo:auth): password failed",
			"%regextime:1% %apphost% %appname:*% : %method%(%string%:%action%): %string% %status%",
			[]int{0, 14, 24, 38, 47, 56, 67, 76},
		},
		{
			"general",
			"jan 15 14:07:04 testserver sudo: pam_unix(sudo:auth): password",
			"%regextime:1% %apphost% %appname%: %method%(%string%:%action%): %string:*% %status%",
			[]int{0, 14, 24, 35, 44, 53, 64, 73},
		},
		{
			"general",
			"jan 15 14:07:04 testserver sudo: pam_unix(sudo:auth): password failed",
			"%regextime:1% %apphost% %appname%: %method:+% (%string%:%action%): %string% %status%",
			[]int{0, 14, 24, 35, 47, 56, 67, 76},
		},
		{
			"general",
			"jan 14 10:15:56 testserver sudo:    gonner : tty=pts/3 ; pwd=/home/gonner ; user=root ; command=/bin/su - ustream",
			"%regextime:1% %apphost% %appname%: %srcuser% : tty=%string% ; pwd=%string% ; user=%dstuser% ; command=%string% - ustream",
			[]int{0, 14, 24, 35, 51, 66, 82, 101},
		},
	}
)

func init() {
	if err := ReadConfig("sequence.toml"); err != nil {
		panic(err)
	}
}

func TestParserMatchPatterns(t *testing.T) {
	parser := NewParser()
	scanner := NewScanner()
	var (
		seq Sequence
		err error
	)

	testset := parsetests
	if config.markSpaces {
		testset = parsetestsnosp
	}

	for _, tc := range testset {
		seq, _, err := scanner.Scan(tc.rule, true, tc.pos)
		require.NoError(t, err, tc.rule)
		err = parser.Add(seq)
		require.NoError(t, err, tc.rule)
	}

	for _, tc := range testset {
		switch tc.format {
		case "json":
			seq, _, err = scanner.ScanJson(tc.msg)

		default:
			seq, _, err = scanner.Scan(tc.msg, false, tc.pos)
		}

		require.NoError(t, err, tc.msg)
		seq, err = parser.Parse(seq)
		require.NoError(t, err, tc.msg)
		r, _ := seq.String()
		require.Equal(t, tc.rule, r, tc.msg+"\n"+seq.PrintTokens())
	}
}

func TestParserParseMessages(t *testing.T) {
	parser := NewParser()
	scanner := NewScanner()
	var pos []int
	var (
		seq Sequence
		err error
	)

	testset := parsetests2
	if config.markSpaces {
		testset = parsetests2nosp
	}

	for _, tc := range testset {
		seq, _, err := scanner.Scan(tc.rule, true, tc.pos)
		require.NoError(t, err, tc.rule)
		err = parser.Add(seq)
		require.NoError(t, err, tc.rule)
	}

	for _, tc := range testset {
		switch tc.format {
		case "json":
			seq, _, err = scanner.ScanJson(tc.msg)

		default:
			seq, _, err = scanner.Scan(tc.msg, false, pos)
		}

		require.NoError(t, err, tc.msg)
		seq, err = parser.Parse(seq)
		require.NoError(t, err, tc.msg)
	}
}

func BenchmarkParserParseMeta(b *testing.B) {
	benchmarkRunParser(b, parsetests2[3])
}

func BenchmarkParserParseNoMeta(b *testing.B) {
	benchmarkRunParser(b, parsetests[1])
}

func benchmarkRunParser(b *testing.B, tc struct {
	format, msg, rule string
	pos               []int
}) {
	parser := NewParser()
	scanner := NewScanner()
	var pos []int
	seq, _, _ := scanner.Scan(tc.rule, true, pos)
	parser.Add(seq)

	seq, _, _ = scanner.Scan(tc.msg, false, pos)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		parser.Parse(seq)
	}
}
