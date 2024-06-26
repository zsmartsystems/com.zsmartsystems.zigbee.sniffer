/**
 * Copyright (c) 2016-2018 by Z-Smart Systems.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 */
package com.zsmartsystems.zigbee.sniffer;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStreamReader;
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
import org.apache.commons.cli.ParseException;

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
    static Integer channelRotationIntervalMillis;
    static Integer channelRotationRangeStart;
    static Integer channelRotationRangeEnd;
    static Long lastChannelRotationTimestamp;
    static int sourcePort;
    static int destinationPort;
    static DatagramSocket client;
    static InetAddress address;
    static SilabsIsdLogFile isdFile;
    static WiresharkPcapFile pcapFile;
    static long startTime = System.nanoTime();
    static ZigBeeDongleEzsp dongle;
    static EmberMfglib emberMfg;
    static EmberNcp emberNcp;
    static Integer deviceId;
    static IeeeAddress localIeeeAddress;
    static long timezone = 0;
    static int wiresharkFileLength = Integer.MAX_VALUE;
    static int wiresharkCounter = 0;
    static String wiresharkFilename;
    static int sequence = 0;
    static long captureMillis;
    static long restartTimer = 30000;

    public static void main(final String[] args) {
        final int ZEP_UDP_PORT = 17754;

        final String serialPortName;
        Integer serialBaud = 115200;
        FlowControl flowControl = FlowControl.FLOWCONTROL_OUT_XONOFF;

        System.out.println("Z-Smart Systems Ember Packet Sniffer");

        Options options = new Options();
        options.addOption(
                Option.builder("p").longOpt("port").argName("port name").hasArg().desc("Set the serial port").build());
        options.addOption(
                Option.builder("b").longOpt("baud").hasArg().argName("baud").desc("Set the port baud rate").build());
        options.addOption(Option.builder("f").longOpt("flow").hasArg().argName("type")
                .desc("Set the flow control (none | hardware | software)").build());
        options.addOption(Option.builder("c").longOpt("channel").hasArg().argName("channel id")
                .desc("Set the ZigBee channel ID").build());
        options.addOption(Option.builder("o").longOpt("rotate").hasArg().argName("seconds")
                .desc("Enable channel rotation and set rotation interval (seconds)").build());
        options.addOption(Option.builder("w").longOpt("rotate-start").hasArg().argName("channel id")
                .desc("Set the channel rotation range start").build());
        options.addOption(Option.builder("e").longOpt("rotate-end").hasArg().argName("channel id")
                .desc("Set the channel rotation range end").build());
        options.addOption(Option.builder("a").longOpt("ipaddr").hasArg().argName("remote IP address")
                .desc("Set the remote IP address").build());
        options.addOption(Option.builder("k").longOpt("sport").hasArg().argName("source port")
                .desc("Set the UDP source port (use 0 to let the system choose)").build());
        options.addOption(Option.builder("r").longOpt("dport").hasArg().argName("destination port")
                .desc("Set the UDP destination port").build());
        options.addOption(Option.builder("s").longOpt("silabs").hasArg().argName("filename")
                .desc("Log data to a Silabs ISD compatible event log").build());
        options.addOption(Option.builder("w").longOpt("pcap").hasArg().argName("filename")
                .desc("Log data to a Wireshark pcap compatible log").build());
        options.addOption(Option.builder("m").longOpt("maxpcap").hasArg().argName("length")
                .desc("Maximum filesize for Wireshark files").build());
        options.addOption(Option.builder("t").longOpt("timeout").hasArg().argName("seconds")
                .desc("NCP restart timeout in seconds").build());
        options.addOption(Option.builder("d").longOpt("device-id").hasArg().argName("device-id")
                .desc("Set the device ID that will be included in ZEP frame").build());
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

            if (cmdline.hasOption("baud")) {
                serialBaud = parseDecimalOrHexInt(cmdline.getOptionValue("baud"));
            }

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
        } catch (ParseException exp) {
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

        if (cmdline.hasOption("timeout")) {
            restartTimer = parseDecimalOrHexInt(cmdline.getOptionValue("timeout")) * 1000;
        }

        if (cmdline.hasOption("maxpcap")) {
            wiresharkFileLength = parseDecimalOrHexInt(cmdline.getOptionValue("maxpcap"));
            wiresharkCounter = 1;
        }

        if (cmdline.hasOption("pcap")) {
            wiresharkFilename = cmdline.getOptionValue("pcap");
            openPcapFile(wiresharkFilename, wiresharkCounter);
        } else {
            pcapFile = null;
        }

        if (cmdline.hasOption("dport")) {
            destinationPort = parseDecimalOrHexInt(cmdline.getOptionValue("dport"));
        } else {
            destinationPort = ZEP_UDP_PORT;
        }

        try {
            if (cmdline.hasOption("ipaddr")) {
                address = InetAddress.getByName(cmdline.getOptionValue("ipaddr"));
            } else {
                address = InetAddress.getByName("127.0.0.1");
            }

            if (cmdline.hasOption("sport")) {
                sourcePort = parseDecimalOrHexInt(cmdline.getOptionValue("sport"));
            } else {
                sourcePort = ZEP_UDP_PORT;
            }

            client = new DatagramSocket(sourcePort);
        } catch (IOException e) {
            e.printStackTrace();
            return;
        }

        if (cmdline.hasOption("channel") && cmdline.hasOption("rotate")) {
            System.err.println("Either a specific channel should be set or scan rotation enabled, but not both");
            return;
        }

        if (cmdline.hasOption("rotate")) {
            channelRotationIntervalMillis = Integer.parseInt(cmdline.getOptionValue("rotate")) * 1000;
            if ((cmdline.hasOption("rotate-start") && !cmdline.hasOption("rotate-end"))
                    || (!cmdline.hasOption("rotate-start") && cmdline.hasOption("rotate-end"))) {
                System.err.println("Channel rotation range (start and end) must be provided together or not at all");
                return;
            }
            if (cmdline.hasOption("rotate-start")) {
                channelRotationRangeStart = parseDecimalOrHexInt(cmdline.getOptionValue("rotate-start"));
                channelRotationRangeEnd = parseDecimalOrHexInt(cmdline.getOptionValue("rotate-end"));
                if (channelRotationRangeStart > channelRotationRangeEnd) {
                    System.err.println("Invalid channel rotation range provided");
                    return;
                }
            } else {
                channelRotationRangeStart = 11;
                channelRotationRangeEnd = 26;
            }
            channelId = channelRotationRangeStart;
        } else {
            if (cmdline.hasOption("channel")) {
                channelId = parseDecimalOrHexInt(cmdline.getOptionValue("channel"));
            } else {
                channelId = 11;
            }
        }

        if (cmdline.hasOption("device-id")) {
            deviceId = parseDecimalOrHexInt(cmdline.getOptionValue("device-id"));
        }

        try {
            BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
            while (!in.ready()) {
                System.out.println("NCP initialisation starting...");

                if (initialiseNcp(serialPortName, serialBaud, flowControl) == false) {
                    System.out.println("Unable to initialise NCP");
                    return;
                }

                System.out.println("NCP initialisation complete...");
                System.out.println("Wireshark destination : " + address + ":" + destinationPort);
                if (channelRotationIntervalMillis != null) {
                    System.out.println("Scanning channel range    : range = [" + channelRotationRangeStart
                            + " , " + channelRotationRangeEnd + "] , interval = " + channelRotationIntervalMillis
                            + " ms");
                } else {
                    System.out.println("Logging on channel    : " + channelId);
                }
                if (deviceId != null) {
                    System.out.println("Device ID    : " + deviceId);
                } else {
                    System.out.println("No device ID set. Last 16 bits of device EUID will be used.");
                }

                captureMillis = System.currentTimeMillis();
                while (!in.ready()) {
                    if (channelRotationIntervalMillis == null) {
                        if (captureMillis < System.currentTimeMillis() - restartTimer) {
                            System.out.println(
                                    "No NCP data received for " + (restartTimer / 1000) + " seconds. Restarting NCP!");
                            break;
                        }
                    } else if (System.currentTimeMillis()
                            - lastChannelRotationTimestamp >= channelRotationIntervalMillis) {
                        final ZigBeeChannel nextChannel = getNextChannel();
                        System.out.println("Setting channel " + nextChannel.getChannel());
                        if (!emberMfg.doMfglibSetChannel(nextChannel)) {
                            System.err.println("Error setting Ember channel");
                            break;
                        }
                        channelId = nextChannel.getChannel();
                        lastChannelRotationTimestamp = System.currentTimeMillis();
                    }
                    Thread.sleep(250);
                }

                System.out.println("NCP shutting down...");
                shutdownNcp();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

        shutdown();
        System.out.println("Sniffer closed.");
    }

    private static void packetReceived(int sequence, int lqi, int rssi, int[] data) {
        captureMillis = System.currentTimeMillis();

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

            if (pcapFile.getLength() > wiresharkFileLength) {
                System.out.println(
                        "Breaking wireshark file " + wiresharkCounter + " at " + pcapFile.getLength() + " bytes.");
                pcapFile.close();
                wiresharkCounter++;
                openPcapFile(wiresharkFilename, wiresharkCounter);
            }
        }

        WiresharkZepFrame zepFrame = new WiresharkZepFrame();
        zepFrame.setLqi(lqi);
        zepFrame.setChannelId(channelId);
        zepFrame.setDeviceId(
                deviceId != null ? deviceId : (localIeeeAddress.getValue()[1] << 8) + localIeeeAddress.getValue()[0]);
        zepFrame.setData(data);
        zepFrame.setSequence(sequence);
        zepFrame.setTimestamp(captureMillis + timezone);
        zepFrame.setRssi(rssi);
        System.out.println(zepFrame);

        byte[] buffer = zepFrame.getBuffer();
        DatagramPacket packet = new DatagramPacket(buffer, buffer.length, address, destinationPort);
        try {
            client.send(packet);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static void shutdownNcp() {
        if (emberMfg != null) {
            emberMfg.doMfglibEnd();
            emberMfg = null;
        }
        dongle.shutdown();
    }

    private static void shutdown() {
        shutdownNcp();

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

    private static void openPcapFile(String filename, int counter) {
        try {
            String file;
            if (counter == 0) {
                file = filename + ".pcap";
            } else {
                file = filename + String.format("-%04d.pcap", counter);
            }
            pcapFile = new WiresharkPcapFile(file);

            WiresharkPcapHeader header = new WiresharkPcapHeader();
            header.setMagicNumber(WiresharkPcapFile.MAGIC_NUMBER_STANDARD);
            header.setNetwork(WiresharkPcapFile.LINKTYPE_IEEE802_15_4_WITHFCS);
            header.setSnapLen(256);
            header.setThisZone((int) timezone);
            header.setSigFigs(3);
            pcapFile.write(header);
        } catch (FileNotFoundException | UnsupportedEncodingException e) {
            e.printStackTrace();
            pcapFile = null;
        }
    }

    private static boolean initialiseNcp(String serialPortName, int serialBaud, FlowControl flowControl) {
        final ZigBeePort serialPort = new ZigBeeSerialPort(serialPortName, serialBaud, flowControl);
        System.out.println("Opened serial port " + serialPortName + " at " + serialBaud);
        dongle = new ZigBeeDongleEzsp(serialPort);

        emberMfg = dongle.getEmberMfglib(new EmberMfglibListener() {
            @Override
            public synchronized void emberMfgLibPacketReceived(int lqi, int rssi, int[] data) {
                packetReceived(sequence++, lqi, rssi, data);
            }
        });

        String ncpVersion = dongle.getFirmwareVersion();
        if (ncpVersion.equals("")) {
            System.err.println("Unable to communicate with Ember NCP");
            shutdown();
            return false;
        }
        System.out.println("Ember NCP version     : " + ncpVersion);

        emberNcp = dongle.getEmberNcp();
        localIeeeAddress = emberNcp.getIeeeAddress();
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
            return false;
        }
        if (!emberMfg.doMfglibSetChannel(ZigBeeChannel.create(channelId))) {
            System.err.println("Error setting Ember channel");
            shutdown();
            return false;
        }

        lastChannelRotationTimestamp = System.currentTimeMillis();

        return true;
    }

    private static ZigBeeChannel getNextChannel() {
        if (channelId == channelRotationRangeEnd) {
            return ZigBeeChannel.create(channelRotationRangeStart);
        }
        return ZigBeeChannel.create(channelId + 1);
    }
}
