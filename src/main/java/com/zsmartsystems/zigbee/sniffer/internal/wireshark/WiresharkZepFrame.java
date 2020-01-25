/**
 * Copyright (c) 2016-2018 by Z-Smart Systems.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 */
package com.zsmartsystems.zigbee.sniffer.internal.wireshark;

import java.util.Arrays;

import com.zsmartsystems.zigbee.sniffer.internal.ZigBeeSnifferBinaryFrame;

/**
 * A class to encapsulate the ZigBee Encapsulation Protocol for Wireshark
 *
 * See https://www.wireshark.org/docs/dfref/z/zep.html
 * <p>
 * ZEP Packets must be received in the following format:
 * <table>
 * <tr>
 * <td>UDP Header</td>
 * <td>ZEP Header</td>
 * <td>IEEE 802.15.4 Packet</td>
 * </tr>
 * <tr>
 * <td>8 bytes</td>
 * <td>16/32 bytes</td>
 * <td><= 127 bytes</td>
 * </tr>
 * </table>
 *
 * <p>
 * ZEP v1 Header will have the following format:
 * <table>
 * <tr>
 * <td>Preamble</td>
 * <td>Version</td>
 * <td>Channel ID</td>
 * <td>Device ID</td>
 * <td>CRC/LQI Mode</td>
 * <td>LQI Val</td>
 * <td>Reserved</td>
 * <td>Length</td>
 * <td>
 * </tr>
 * <tr>
 * <td>2 bytes</td>
 * <td>1 byte</td>
 * <td>1 byte</td>
 * <td>2 bytes</td>
 * <td>1 byte</td>
 * <td>1 byte</td>
 * <td>7 bytes</td>
 * <td>1 byte</td>
 * </tr>
 * </table>
 *
 * <p>
 * ZEP v2 Header will have the following format (if type=1/Data):
 * <table>
 * <tr>
 * <td>Preamble</td>
 * <td>Version</td>
 * <td>Type</td>
 * <td>Channel ID</td>
 * <td>Device ID</td>
 * <td>CRC/LQI Mode</td>
 * <td>LQI Val</td>
 * <td>NTP Timestamp</td>
 * <td>Sequence#</td>
 * <td>Reserved</td>
 * <td>Length</td>
 * </tr>
 * <tr>
 * <td>2 bytes</td>
 * <td>1 byte</td>
 * <td>1 byte</td>
 * <td>1 byte</td>
 * <td>2 bytes</td>
 * <td>1 byte</td>
 * <td>1 byte</td>
 * <td>8 bytes</td>
 * <td>4 bytes</td>
 * <td>10 bytes</td>
 * <td>1 byte</td>
 * </tr>
 * </table>
 *
 * <p>
 * ZEP v2 Header will have the following format (if type=2/Ack):
 * <table>
 * <tr>
 * <td>Preamble</td>
 * <td>Version</td>
 * <td>Type</td>
 * <td>Sequence#</td>
 * </tr>
 * <tr>
 * <td>2 bytes</td>
 * <td>1 byte</td>
 * <td>1 byte</td>
 * <td>4 bytes</td>
 * </tr>
 * </tr>
 * </table>
 *
 * @author Chris Jackson
 *
 */
public class WiresharkZepFrame extends ZigBeeSnifferBinaryFrame {
    private int channelId;
    private int deviceId = 1;
    private int lqi;
    private boolean lqiMode = false;
    private int sequence;
    private int rssi;
    private long timestamp;
    private int protocolType = 1;
    private int protocolVersion = 2;

    /**
     * baseline NTP time if bit-0=0 -> 7-Feb-2036 @ 06:28:16 UTC
     */
    protected static final long msb0baseTime = 2085978496000L;

    /**
     * baseline NTP time if bit-0=1 -> 1-Jan-1900 @ 01:00:00 UTC
     */
    protected static final long msb1baseTime = -2208988800000L;

    public WiresharkZepFrame() {
    }

    /**
     * @param length the length to set
     */
    public void setLength(int length) {
        this.length = length;
    }

    /**
     * @param channelId the channelId to set
     */
    public void setChannelId(int channelId) {
        this.channelId = channelId;
    }

    /**
     * @param deviceId the deviceId to set
     */
    public void setDeviceId(int deviceId) {
        this.deviceId = deviceId;
    }

    /**
     * @param lqi the lqi to set
     */
    public void setLqi(int lqi) {
        this.lqi = lqi;
    }

    /**
     * @param lqiMode the lqiMode to set
     */
    public void setLqiMode(boolean lqiMode) {
        this.lqiMode = lqiMode;
    }

    /**
     * @param seqNum the sequence to set
     */
    public void setSequence(int seqNum) {
        this.sequence = seqNum;
    }

    /**
     * @param type the protocolType to set
     */
    public void setProtocolType(int protocolType) {
        this.protocolType = protocolType;
    }

    public void serRssi(int rssi) {
        this.rssi = rssi;
    }

    /**
     * @param protocolVersion the protocolVersion to set
     */
    public void setProtocolVersion(int protocolVersion) {
        this.protocolVersion = protocolVersion;
    }

    public void setTimestamp(long timestamp) {
        this.timestamp = timestamp;
    }

    public byte[] getBuffer() {
        // Patch FCS to be compatible with CC24xx format
        data[data.length - 2] = rssi;
        data[data.length - 1] = 0x80;

        serializeInt8(0x45);
        serializeInt8(0x58);
        serializeInt8(protocolVersion);
        serializeInt8(protocolType);
        serializeInt8(channelId);
        serializeInt16(deviceId);
        serializeBoolean(lqiMode);
        serializeInt8(lqi);
        serializeLong(toNtpTime(timestamp));
        serializeInt32(sequence);

        // Reserved bytes
        length += 10;

        serializeInt8(data.length);
        serializeData(data);

        return Arrays.copyOfRange(buffer, 0, length);
    }

    /***
     * Converts Java time to 64-bit NTP time representation.
     *
     * @param time Java time
     * @return NTP timestamp representation of Java time value.
     */
    private long toNtpTime(long time) {
        boolean useBase1 = time < msb0baseTime; // time < Feb-2036
        long baseTime;
        if (useBase1) {
            baseTime = time - msb1baseTime; // dates <= Feb-2036
        } else {
            // if base0 needed for dates >= Feb-2036
            baseTime = time - msb0baseTime;
        }

        long seconds = baseTime / 1000;
        long fraction = ((baseTime % 1000) * 0x100000000L) / 1000;

        if (useBase1) {
            seconds |= 0x80000000L; // set high-order bit if msb1baseTime 1900 used
        }

        return seconds << 32 | fraction;
    }

    @Override
    public String toString() {
        StringBuilder builder = new StringBuilder(200);
        builder.append("WiresharkZepFrame [sequence=");
        builder.append(String.format("%08X", sequence));
        builder.append(", lqi=");
        builder.append(lqi);
        builder.append(", data={");
        boolean first = true;
        for (int val : data) {
            if (!first) {
                builder.append(' ');
            }
            first = false;
            builder.append(String.format("%02X", val));
        }
        builder.append("}]");
        return builder.toString();
    }

}
