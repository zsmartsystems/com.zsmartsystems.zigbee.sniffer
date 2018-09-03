/**
 * Copyright (c) 2016-2018 by Z-Smart Systems.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 */
package com.zsmartsystems.zigbee.sniffer;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.TimeZone;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;

import com.zsmartsystems.zigbee.IeeeAddress;
import com.zsmartsystems.zigbee.ZigBeeChannel;
import com.zsmartsystems.zigbee.dongle.ember.EmberMfglib;
import com.zsmartsystems.zigbee.dongle.ember.EmberMfglibListener;
import com.zsmartsystems.zigbee.dongle.ember.EmberNcp;
import com.zsmartsystems.zigbee.dongle.ember.ZigBeeDongleEzsp;
import com.zsmartsystems.zigbee.serial.ZigBeeSerialPort;
import com.zsmartsystems.zigbee.sniffer.internal.silabs.SilabsAdapter;
import com.zsmartsystems.zigbee.sniffer.internal.silabs.SilabsIsdLogFile;
import com.zsmartsystems.zigbee.sniffer.internal.silabs.SilabsPacketEm350Rx;
import com.zsmartsystems.zigbee.sniffer.internal.silabs.SilabsPrintf;
import com.zsmartsystems.zigbee.sniffer.internal.silabs.SilabsVersion;
import com.zsmartsystems.zigbee.sniffer.internal.wireshark.WiresharkPcapFile;
import com.zsmartsystems.zigbee.sniffer.internal.wireshark.WiresharkPcapFrame;
import com.zsmartsystems.zigbee.sniffer.internal.wireshark.WiresharkPcapHeader;
import com.zsmartsystems.zigbee.sniffer.internal.wireshark.WiresharkZepFrame;
import com.zsmartsystems.zigbee.transport.ZigBeePort;
import com.zsmartsystems.zigbee.transport.ZigBeePort.FlowControl;

/**
 * This class uses the {@link ZigBeeDongleEzsp} class to create a ZigBee sniffer and make the data available to
 * Wireshark and optionally write to a Silabs ISD event file.
 *
 * @author Chris Jackson
 *
 */
public class ZigBeeSniffer {
    static Integer channelId;
    static int clientPort;
    static DatagramSocket client;
    static InetAddress address;
    static SilabsIsdLogFile isdFile;
    static WiresharkPcapFile pcapFile;
    static long startTime = System.nanoTime();
    static ZigBeeDongleEzsp dongle;
    static EmberMfglib emberMfg;
    static EmberNcp emberNcp;
    static long timezone = 0;

    public static void main(final String[] args) {
        final int ZEP_UDP_PORT = 17754;

        final String serialPortName;
        final Integer serialBaud;
        FlowControl flowControl = null;

        System.out.println("Z-Smart Systems Ember Packet Sniffer");

        Options options = new Options();
        options.addOption(Option.builder("p").longOpt("port").argName("port name").hasArg().desc("Set the port")
                .required().build());
        options.addOption(
                Option.builder("b").longOpt("baud").hasArg().argName("baud").desc("Set the port baud rate").build());
        options.addOption(Option.builder("f").longOpt("flow").hasArg().argName("type")
                .desc("Set the flow control (none | hardware | software)").build());
        options.addOption(Option.builder("c").longOpt("channel").hasArg().argName("channel id")
                .desc("Set the ZigBee channel ID").build());
        options.addOption(Option.builder("a").longOpt("ipaddr").hasArg().argName("remote IP address")
                .desc("Set the remote IP address").build());
        options.addOption(Option.builder("r").longOpt("ipport").hasArg().argName("remote IP port")
                .desc("Set the remote IP port").build());
        options.addOption(Option.builder("s").longOpt("silabs").hasArg().argName("filename")
                .desc("Log data to a Silabs ISD compatible event log").build());
        options.addOption(Option.builder("p").longOpt("pcap").hasArg().argName("filename")
                .desc("Log data to a Wireshark pcap compatible log").build());
        options.addOption(Option.builder("l").longOpt("local").desc("Log times in local time").build());
        options.addOption(Option.builder("?").longOpt("help").desc("Print usage information").build());

        CommandLine cmdline;
        try {
            CommandLineParser parser = new DefaultParser();
            cmdline = parser.parse(options, args);

            if (cmdline.hasOption("help")) {
                HelpFormatter formatter = new HelpFormatter();
                formatter.printHelp("ZigBeeSniffer", options);
                return;
            }
            if (!cmdline.hasOption("port")) {
                System.err.println("Serial port must be specified with the 'port' option");
                return;
            }

            serialPortName = cmdline.getOptionValue("port");
            serialBaud = parseDecimalOrHexInt(cmdline.getOptionValue("baud"));

            if (cmdline.hasOption("flow")) {
                switch (cmdline.getOptionValue("flow").toLowerCase()) {
                    case "software":
                        flowControl = FlowControl.FLOWCONTROL_OUT_XONOFF;
                        break;
                    case "hardware":
                        flowControl = FlowControl.FLOWCONTROL_OUT_RTSCTS;
                        break;
                    case "none":
                        flowControl = FlowControl.FLOWCONTROL_OUT_NONE;
                        break;
                    default:
                        System.err.println(
                                "Unknown flow control option used: " + cmdline.getOptionValue("flow").toLowerCase());
                        return;
                }
            }
        } catch (org.apache.commons.cli.ParseException exp) {
            System.err.println("Parsing command line failed.  Reason: " + exp.getMessage());
            return;
        }

        if (cmdline.hasOption("local")) {
            TimeZone tz = TimeZone.getDefault();
            timezone = tz.getOffset(new Date().getTime());

            System.out.println("Using timezone " + tz.getDisplayName() + " (" + timezone + ")");
        }
        if (cmdline.hasOption("silabs")) {
            try {
                isdFile = new SilabsIsdLogFile(cmdline.getOptionValue("silabs"));
            } catch (FileNotFoundException | UnsupportedEncodingException e) {
                e.printStackTrace();
                return;
            }
        } else {
            isdFile = null;
        }

        if (cmdline.hasOption("pcap")) {
            try {
                pcapFile = new WiresharkPcapFile(cmdline.getOptionValue("pcap"));

                WiresharkPcapHeader header = new WiresharkPcapHeader();
                header.setMagicNumber(WiresharkPcapFile.MAGIC_NUMBER_STANDARD);
                header.setNetwork(WiresharkPcapFile.LINKTYPE_IEEE802_15_4_WITHFCS);
                header.setSnapLen(256);
                header.setThisZone((int) timezone);
                header.setSigFigs(3);
                pcapFile.write(header);
            } catch (FileNotFoundException | UnsupportedEncodingException e) {
                e.printStackTrace();
                return;
            }
        } else {
            pcapFile = null;
        }

        try {
            if (cmdline.hasOption("ipaddr")) {
                address = InetAddress.getByName(cmdline.getOptionValue("ipaddr"));
            } else {
                address = InetAddress.getByName("127.0.0.1");
            }

            if (cmdline.hasOption("ipport")) {
                clientPort = parseDecimalOrHexInt(cmdline.getOptionValue("ipport"));
            } else {
                clientPort = ZEP_UDP_PORT;
            }
            client = new DatagramSocket(ZEP_UDP_PORT);
        } catch (IOException e) {
            e.printStackTrace();
            return;
        }

        if (cmdline.hasOption("channel")) {
            channelId = parseDecimalOrHexInt(cmdline.getOptionValue("channel"));
        } else {
            channelId = 11;
        }

        final ZigBeePort serialPort = new ZigBeeSerialPort(serialPortName, serialBaud, flowControl);
        System.out.println("Opened serial port " + serialPortName + " at " + serialBaud);
        dongle = new ZigBeeDongleEzsp(serialPort);

        emberMfg = dongle.getEmberMfglib(new EmberMfglibListener() {
            private int sequence = 0;

            @Override
            public synchronized void emberMfgLibPacketReceived(int lqi, int rssi, int[] data) {
                packetReceived(sequence++, lqi, rssi, data);
            }
        });

        String ncpVersion = dongle.getFirmwareVersion();
        if (ncpVersion.equals("")) {
            System.err.println("Unable to communicate with Ember NCP");
            shutdown();
            return;
        }
        System.out.println("Ember NCP version     : " + ncpVersion);

        emberNcp = dongle.getEmberNcp();
        IeeeAddress localIeeeAddress = emberNcp.getIeeeAddress();
        System.out.println("Ember NCP EUI         : " + localIeeeAddress);

        if (isdFile != null) {
            SilabsAdapter adapter = new SilabsAdapter();
            adapter.setAddress(localIeeeAddress);
            isdFile.write(adapter);
            SilabsVersion version = new SilabsVersion();
            version.setVersion(dongle.getFirmwareVersion());
            isdFile.write(version);
            DateFormat dateFormat = new SimpleDateFormat("yyyy/MM/dd HH:mm:ss");
            Date date = new Date();
            SilabsPrintf printf = new SilabsPrintf();
            printf.setString("Logging started at " + dateFormat.format(date));
            isdFile.write(printf);
        }

        if (!emberMfg.doMfglibStart()) {
            System.err.println("Error starting Ember mfglib");
            shutdown();
            return;
        }
        if (!emberMfg.doMfglibSetChannel(ZigBeeChannel.create(channelId))) {
            System.err.println("Error setting Ember channel");
            shutdown();
            return;
        }

        System.out.println("Wireshark destination : " + address + ":" + clientPort);
        System.out.println("Logging on channel    : " + channelId);

        try {
            System.in.read();
        } catch (IOException e) {
            e.printStackTrace();
        }

        shutdown();

        System.out.println("Sniffer closed.");
    }

    private static void packetReceived(int sequence, int lqi, int rssi, int[] data) {
        long captureMillis = System.currentTimeMillis();

        if (isdFile != null) {
            SilabsPacketEm350Rx silabsPacket = new SilabsPacketEm350Rx();
            silabsPacket.setSequence(sequence & 0xFF);
            silabsPacket.setTimestamp((System.nanoTime() - startTime) / 1000);
            silabsPacket.setData(data);
            silabsPacket.setLqi(lqi);
            silabsPacket.setRssi(rssi);
            silabsPacket.setChannel(channelId);
            isdFile.write(silabsPacket);
        }

        if (pcapFile != null) {
            long seconds = (captureMillis + timezone) / 1000;
            WiresharkPcapFrame pcapPacket = new WiresharkPcapFrame();
            pcapPacket.setSeconds((int) (seconds));
            pcapPacket.setMicroseconds((int) (captureMillis - (seconds * 1000)) * 1000);
            pcapPacket.setData(data);

            pcapFile.write(pcapPacket);
        }

        WiresharkZepFrame zepFrame = new WiresharkZepFrame();
        zepFrame.setLqi(lqi);
        zepFrame.setChannelId(channelId);
        zepFrame.setData(data);
        zepFrame.setSequence(sequence);
        zepFrame.setTimestamp(captureMillis + timezone);
        System.out.println(zepFrame);

        byte[] buffer = zepFrame.getBuffer();
        DatagramPacket packet = new DatagramPacket(buffer, buffer.length, address, clientPort);
        try {
            client.send(packet);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static void shutdown() {
        if (emberMfg != null) {
            emberMfg.doMfglibEnd();
            emberMfg = null;
        }
        dongle.shutdown();
        client.close();
        if (isdFile != null) {
            isdFile.close();
            isdFile = null;
        }
        if (pcapFile != null) {
            pcapFile.close();
            pcapFile = null;
        }
    }

    /**
     * Parse decimal or hexadecimal integer.
     *
     * @param strVal the string value to parse
     * @return the parsed integer value
     */
    private static int parseDecimalOrHexInt(String strVal) {
        int radix = 10;
        String number = strVal;
        if (number.startsWith("0x")) {
            number = number.substring(2);
            radix = 16;
        }
        return Integer.parseInt(number, radix);
    }
}
