# com.zsmartsystems.zigbee.sniffer

This project uses the ```com.zsmartsystems.zigbee.dongle.ember``` driver to provide a ZigBee sniffer interface for Wireshark. The software will connect to an Ember dongle using a serial interface, and send UDP packets on port 17754 which can be received and displayed by Wireshark.

To use Wireshark, the loopback interface needs to be selected, and then a filter ```udp port 17754``` is used to only display ZigBee packets.
