# com.zsmartsystems.zigbee.sniffer

This project uses the ```com.zsmartsystems.zigbee.dongle.ember``` driver to provide a ZigBee sniffer interface for Wireshark, and optionally write the data to a Silabs compatible event log. The software will connect to an Ember dongle using a serial interface, and send UDP packets on port 17754 which can be received and displayed by Wireshark.

To use Wireshark, the loopback interface needs to be selected, and then a filter ```udp port 17754``` is used to only display ZigBee packets.

```
usage: ZigBeeSniffer
-?,--help                         Print usage information
-a,--ipaddr <remote IP address>   Set the remote IP address
-b,--baud <baud>                  Set the port baud rate
-c,--channel <channel id>         Set the ZigBee channel ID
-o,--rotate <seconds>             Enable channel rotation and set rotation interval (seconds)
-w,--rotate-start <channel id>    Set the channel rotation range start
-e,--rotate-end <channel id>      Set the channel rotation range end
-f,--flow <type>                  Set the flow control (none | hardware | software)
-l,--local                        Log times in local time
-m,--maxpcap <length>             Maximum filesize for Wireshark files
-p,--port <port name>             Set the port
-r,--ipport <remote IP port>      Set the remote IP port
-s,--silabs <filename>            Log data to a Silabs ISD compatible event log
-t,--timeout <seconds>            NCP restart timeout in seconds
-w,--pcap <filename>              Log data to a Wireshark pcap compatible log
```

Note that the IP address will default to the local host on the assumption that you are running Wireshark on the same computer as the sniffer. The ```ipport``` will default to 17754 which is the port used for the ZigBee Encapsulation Protocol - changing this may stop Wireshark displaying ZigBee data.

Example command line -:

```
java -jar ZigBeeSniffer.jar -port /dev/tty.SLAB_USBtoUART -baud 115200 -flow hardware
```

The software will print an output to the console for each packet that is received to allow confirmation it is working. When running Wireshark, these should also be seen in the Wireshark window.

If the NCP fails to receive a valid frame with the timeout period set with the ```timeout``` command line parameter, then the NCP will be restarted. This will allow the sniffer to recover from serial port or NCP communications problems. The timer defaults to 30 seconds.

A compiled JAR file can be found [here](https://www.cd-jackson.com/downloads/ZigBeeSniffer.jar) along with [further documentation](https://www.cd-jackson.com/downloads/ZigBeeWiresharkSniffer.pdf).
