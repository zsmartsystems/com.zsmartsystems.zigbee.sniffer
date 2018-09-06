/**
 * Copyright (c) 2016-2018 by Z-Smart Systems.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 */
package com.zsmartsystems.zigbee.sniffer.internal.silabs;

/**
 * A class to encapsulate the ZigBee ISD log for Silabs Simplicity Studio
 * <p>
 * [721629332 576 16908322 Packet B1] [ember01] [0A 03 08 E3 FF FF FF FF 07 56 A7 01]
 * <p>
 * These fields are decoded as follows:
 * <p>
 * <li>721629332 - Timestamp in microseconds when event completed (start time can be inferred from subtracting Duration
 * from this value)
 * <li>576 - Event duration in microseconds.
 * <li>16908322 - Event type ID. This varies for different kinds of trace events (Packets, EZSP traces, NodeInfo traces,
 * Reset traces, etc.) The one shown denotes a Packet event. These type IDs are not currently documented, so you would
 * need to derive this empirically through testing if you wish to parse it. Some common ones are 131131 (NodeInfo),
 * 131138 (Stack Version), 131132 (EZSP), 131133 (ASH), 16908322 (EM250 TX), 16908323 (EM250 RX), 16908324 (EM350 TX),
 * 16908325 (EM350 RX), 16908329 (EFR TX), 16908330 (EFR RX).
 * <li>Packet - Event type string. This is the friendly name (as ASCII text) for the event type and will match what
 * Network Analyzer displays in the event window for this event type.
 * <li>B1 - Debug protocol's sequence number from the capture source (used to detect gaps in the capture stream)
 * <li>ember01 - Source device where event was captured.
 * <li>[0A 03 ... 01] - Event data bytes (prior to any decryption; includes any RadioInfo data appended to end of
 * packets by the hardware). Note that the first byte for Packet events is generally the Length byte, which represents
 * (in hexadecimal) the number of bytes (including the Length byte itself) in the transmitted/received packet, up to and
 * including the CRC16 and not including any status/quality bytes appended by the radio during TX/RX activity.
 * <p>
 * Above explanation from this link -:
 * https://www.silabs.com/community/wireless/zigbee-and-thread/knowledge-base.entry.html/2012/06/28/can_i_examine_captur-uFfw
 *
 * @author Chris Jackson
 *
 */
public abstract class SilabsIsdFrame {
    protected Integer sequence;
    protected String frameType;
    private long timestamp;
    protected int eventDuration = 0;
    protected int packetType = 0;

    private StringBuilder builder = new StringBuilder();

    private boolean first;

    public SilabsIsdFrame() {
    }

    /**
     * @param seqNum the sequence to set
     */
    public void setSequence(int sequence) {
        this.sequence = sequence;
    }

    /**
     * @param l the timestamp to set
     */
    public void setTimestamp(long l) {
        this.timestamp = l;
    }

    protected void formatValue(Integer value) {
        if (!first) {
            builder.append(' ');
        }
        first = false;
        if (value == null) {
            builder.append("XX");
        } else {
            builder.append(String.format("%02X", value));
        }
    }

    protected void getHeader() {
        first = true;
        builder.append("[");
        builder.append(timestamp);
        builder.append(' ');
        builder.append(eventDuration);
        builder.append(' ');
        builder.append(packetType);
        builder.append(' ');
        builder.append(frameType);
        builder.append(' ');
        formatValue(sequence);
        builder.append("] [ZSmartSystems] [");
        first = true;
    }

    protected String terminateLog() {
        builder.append(']');
        return builder.toString();
    }

    public abstract String getBuffer();
}
