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
 * The pcap file has a global header containing some global information followed by zero or more records for each
 * captured packet, looking like this:
 *
 * <pre>
 * typedef struct pcap_hdr_s {
 *        uint32 magic_number;  // magic number
 *        uint16 version_major; // major version number
 *        uint16 version_minor; // minor version number
 *        int32  thiszone;      // GMT to local correction
 *        uint32 sigfigs;       // accuracy of timestamps
 *        uint32 snaplen;       // max length of captured packets, in octets
 *        uint32 network;       // data link type
 * };
 * </pre>
 * <p>
 * <ul>
 * <li>magic_number: used to detect the file format itself and the byte ordering. The writing application
 * writes 0xa1b2c3d4 with it's native byte ordering format into this field. The reading application will read either
 * 0xa1b2c3d4 (identical) or 0xd4c3b2a1 (swapped). If the reading application reads the swapped 0xd4c3b2a1 value, it
 * knows that all the following fields will have to be swapped too. For nanosecond-resolution files, the writing
 * application writes 0xa1b23c4d, with the two nibbles of the two lower-order bytes swapped, and the reading application
 * will read either 0xa1b23c4d (identical) or 0x4d3cb2a1 (swapped).
 * <li>version_major, version_minor: the version number of this file format (current version is 2.4)
 * <li>thiszone: the correction time in seconds between GMT (UTC) and the local timezone of the following packet header
 * timestamps. Examples: If the timestamps are in GMT (UTC), thiszone is simply 0. If the timestamps are in Central
 * European time (Amsterdam, Berlin, ...) which is GMT + 1:00, thiszone must be -3600. In practice, time stamps are
 * always in GMT, so thiszone is always 0.
 * <li>sigfigs: in theory, the accuracy of time stamps in the capture; in practice, all tools set it to 0.
 * <li>snaplen: the "snapshot length" for the capture (typically 65535 or even more, but might be limited by the user).
 * <li>network: link-layer header type, specifying the type of headers at the beginning of the packet (e.g. 1 for
 * Ethernet, see tcpdump.org's link-layer header types page for details); this can be various types such as 802.11,
 * 802.11 with various radio information, PPP, Token Ring, FDDI, etc.
 * </ul>
 * <p>
 * Relevant network layers are -:
 * <ul>
 * <li>195: LINKTYPE_IEEE802_15_4_WITHFCS
 * <li>215: LINKTYPE_IEEE802_15_4_NONASK_PHY
 * <li>230: LINKTYPE_IEEE802_15_4_NOFCS
 * </ul>
 * <p>
 *
 *
 * @author Chris Jackson
 *
 */
public class WiresharkPcapHeader extends ZigBeeSnifferBinaryFrame {
    private int magic_number;
    private int version_major;
    private int version_minor;
    private int thiszone;
    private int sigfigs;
    private int snaplen;
    private int network;

    /**
     * @param magic_number the magic_number to set
     */
    public void setMagicNumber(int magic_number) {
        this.magic_number = magic_number;
    }

    /**
     * @param version_major the version_major to set
     */
    public void setVersionMajor(int version_major) {
        this.version_major = version_major;
    }

    /**
     * @param version_minor the version_minor to set
     */
    public void setVersionMinor(int version_minor) {
        this.version_minor = version_minor;
    }

    /**
     * @param thiszone the thiszone to set
     */
    public void setThisZone(int thiszone) {
        this.thiszone = thiszone;
    }

    /**
     * @param sigfigs the sigfigs to set
     */
    public void setSigFigs(int sigfigs) {
        this.sigfigs = sigfigs;
    }

    /**
     * @param snaplen the snaplen to set
     */
    public void setSnapLen(int snaplen) {
        this.snaplen = snaplen;
    }

    /**
     * @param network the network to set
     */
    public void setNetwork(int network) {
        this.network = network;
    }

    public byte[] getBuffer() {
        serializeInt32(magic_number);
        serializeInt16(version_major);
        serializeInt16(version_minor);
        serializeInt32(thiszone);
        serializeInt32(sigfigs);
        serializeInt32(snaplen);
        serializeInt32(network);

        return Arrays.copyOfRange(buffer, 0, length);
    }
}
