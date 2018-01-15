# Firewall

This is a simple firewall implementation.

## Test

The test code is already included in the source code. The following is the
snippet of my testing code. Basically, it is tried each of the rules on the
iptables.csv. Then123.45.6.77, I enumerated some of the "Block" rules and check if the
result is expected.

```java
boolean ok = fw.acceptPacket("inbound", "tcp", 80, "192.168.1.2");
System.out.println(ok);
// match second rule
ok = fw.acceptPacket("outbound", "udp", 10234, "192.168.10.11");
System.out.println(ok);
// match third rule
ok = fw.acceptPacket("inbound", "udp", 53, "192.168.2.1");
System.out.println(ok);
// match fourth rule
ok = fw.acceptPacket("outbound", "udp", 2000, "52.12.48.92");
System.out.println(ok);
// match fifth rule
ok = fw.acceptPacket("inbound", "tcp", 2344, "123.45.66.255");
System.out.println(ok);
boolean nok = fw.acceptPacket("inbound", "tcp", 81, "192.168.1.2");
System.out.println(nok);
nok = fw.acceptPacket("inbound", "tcp", 10234, "192.168.10.11");
System.out.println(nok);
nok = fw.acceptPacket("outbound","udp", 2001,"52.12.48.92");
System.out.println(nok);
nok = fw.acceptPacket("inbound","tcp",2255, "123.45.6.77");
System.out.println(nok);
```
## Things to point out
The implementation of the Firewall library is twofold. First it loads the
iptable csv, and is based on the rule to check if "allow" or "block". Since
loading work is just a one time job, but check allow or not is more
frequently. Therefore, I decide to make my work load when instantiate (it is
    also written in the source code). Building the set for each
direction/protocol/IP/port seems to consume lots of memory and time, but the
reward is hight too. We can check allow or not in just O(1) time complexity.
However, a key comparison can still be time-consuming task. Therefore, I used
maps and hash code to shorten the length of the key as well.

## Refine and Optimization
I left several TODO and FIXME in the source code to point out things I can do
if I have more time. If I have time, I am also considering storing range
instead of simple point one by one.

## Preference team
I am really interested in Platform team, nevertheless, all three team looks cool
and great. The overall ranking in this three areas.
  1. Platform team
  2. Data team
  3. Policy team
