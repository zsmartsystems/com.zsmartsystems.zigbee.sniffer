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
 * Each captured packet starts with (any byte alignment possible):
 * <p>
 *
 * <pre>
 * typedef struct pcaprec_hdr_s {
 *       uint32 ts_sec;         // timestamp seconds
 *       uint32 ts_usec;        // timestamp microseconds
 *       uint32 incl_len;       // number of octets of packet saved in file
 *       uint32 orig_len;       // actual length of packet
 * };
 * </pre>
 * <ul>
 * <li>ts_sec: the date and time when this packet was captured. This value is in seconds since January 1, 1970 00:00:00
 * GMT; this is also known as a UN*X time_t. You can use the ANSI C time() function from time.h to get this value, but
 * you might use a more optimized way to get this timestamp value. If this timestamp isn't based on GMT (UTC), use
 * thiszone from the global header for adjustments.
 * <li>ts_usec: in regular pcap files, the microseconds when this packet was captured, as an offset to ts_sec. In
 * nanosecond-resolution files, this is, instead, the nanoseconds when the packet was captured, as an offset to ts_sec
 * /!\ Beware: this value shouldn't reach 1 second (in regular pcap files 1 000 000; in nanosecond-resolution files, 1
 * 000 000 000); in this case ts_sec must be increased instead!
 * <li>incl_len: the number of bytes of packet data actually captured and saved in the file. This value should never
 * become larger than orig_len or the snaplen value of the global header.
 * <li>orig_len: the length of the packet as it appeared on the network when it was captured. If incl_len and orig_len
 * differ, the actually saved packet size was limited by snaplen.
 * </ul>
 * <p>
 * The actual packet data will immediately follow the packet header as a data blob of incl_len bytes without a specific
 * byte alignment.
 * <p>
 *
 * @author Chris Jackson
 *
 */
public class WiresharkPcapFrame extends ZigBeeSnifferBinaryFrame {
    private int seconds;
    private int microseconds;

    /**
     * @param seconds the seconds to set
     */
    public void setSeconds(int seconds) {
        this.seconds = seconds;
    }

    /**
     * @param microseconds the microseconds to set
     */
    public void setMicroseconds(int microseconds) {
        this.microseconds = microseconds;
    }

    public byte[] getBuffer() {
        serializeInt32(seconds);
        serializeInt32(microseconds);
        serializeInt32(data.length);
        serializeInt32(data.length);
        serializeData(data);

        return Arrays.copyOfRange(buffer, 0, length);
    }
}
