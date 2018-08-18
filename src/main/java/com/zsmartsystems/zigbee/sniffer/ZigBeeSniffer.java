/**
 * Copyright (c) 2016-2018 by the respective copyright holders.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 */
package com.zsmartsystems.zigbee.sniffer;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;

import com.zsmartsystems.zigbee.ZigBeeChannel;
import com.zsmartsystems.zigbee.dongle.ember.EmberMfglib;
import com.zsmartsystems.zigbee.dongle.ember.EmberMfglibListener;
import com.zsmartsystems.zigbee.dongle.ember.ZigBeeDongleEzsp;
import com.zsmartsystems.zigbee.serial.ZigBeeSerialPort;
import com.zsmartsystems.zigbee.transport.ZigBeePort;
import com.zsmartsystems.zigbee.transport.ZigBeePort.FlowControl;

/**
 * This class uses the {@link ZigBeeDongleEzsp} class to create a ZigBee sniffer and make the data available to
 * Wireshark.
 *
 * @author Chris Jackson
 *
 */
public class ZigBeeSniffer {
    public static void main(final String[] args) {
        final int ZEP_UDP_PORT = 17754;

        final String serialPortName;
        final Integer serialBaud;
        final Integer channelId;
        FlowControl flowControl = null;
        final int clientPort;
        DatagramSocket client;
        InetAddress address;

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
                .desc("Set the remote IP address").build());
        options.addOption(Option.builder("?").longOpt("help").desc("Print usage information").build());

        CommandLine cmdline;
        try {
            CommandLineParser parser = new DefaultParser();
            cmdline = parser.parse(options, args);

            if (cmdline.hasOption("help")) {
                HelpFormatter formatter = new HelpFormatter();
                formatter.printHelp("zigbeeconsole", options);
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
        final ZigBeeDongleEzsp dongle = new ZigBeeDongleEzsp(serialPort);
        EmberMfglib emberMfg = dongle.getEmberMfglib(new EmberMfglibListener() {
            private int sequence = 0;

            @Override
            public synchronized void emberMfgLibPacketReceived(int linkQuality, int rssi, int[] data) {
                // Patch FCS to be compatible with CC24xx format
                data[data.length - 2] = rssi;
                data[data.length - 1] = 0x80;

                WiresharkZepFrame zepFrame = new WiresharkZepFrame();
                zepFrame.setLqi(linkQuality);
                zepFrame.setChannelId(channelId);
                zepFrame.setData(data);
                zepFrame.setSequence(sequence++);
                System.out.println(zepFrame);

                byte[] buffer = zepFrame.getBuffer();

                DatagramPacket packet = new DatagramPacket(buffer, buffer.length, address, clientPort);
                try {
                    client.send(packet);
                } catch (IOException e) {
                    // TODO Auto-generated catch block
                    e.printStackTrace();
                }
            }
        });
        if (!emberMfg.doMfglibStart()) {
            System.err.println("Error starting Ember mfglib");
            dongle.shutdown();
            client.close();
            return;
        }
        if (!emberMfg.doMfglibSetChannel(ZigBeeChannel.create(channelId))) {
            System.err.println("Error setting Ember channel");
            dongle.shutdown();
            client.close();
            return;
        }

        try {
            System.in.read();
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        emberMfg.doMfglibEnd();
        dongle.shutdown();
        client.close();
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
