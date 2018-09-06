# com.zsmartsystems.zigbee.sniffer

This project uses the ```com.zsmartsystems.zigbee.dongle.ember``` driver to provide a ZigBee sniffer interface for Wireshark, and optionally write the data to a Silabs compatible event log. The software will connect to an Ember dongle using a serial interface, and send UDP packets on port 17754 which can be received and displayed by Wireshark.

To use Wireshark, the loopback interface needs to be selected, and then a filter ```udp port 17754``` is used to only display ZigBee packets.

```
usage: ZigBeeSniffer
-?,--help                         Print usage information
-a,--ipaddr <remote IP address>   Set the remote IP address
-b,--baud <baud>                  Set the port baud rate
-c,--channel <channel id>         Set the ZigBee channel ID
-f,--flow <type>                  Set the flow control (none | hardware | software)
-l,--local                        Log times in local time
-p,--port <port name>             Set the port
-r,--ipport <remote IP port>      Set the remote IP port
-s,--silabs <filename>            Log data to a Silabs ISD compatible event log
-w,--pcap <filename>              Log data to a Wireshark pcap compatible log
```

```
java -jar ZigBeeSniffer.jar -port /dev/tty.SLAB_USBtoUART -baud 115200 -flow hardware
```

A compiled JAR file can be found [here](https://www.cd-jackson.com/downloads/ZigBeeSniffer.jar).
