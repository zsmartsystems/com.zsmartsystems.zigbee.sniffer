/**
 * Copyright (c) 2016-2018 by Z-Smart Systems.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 */
package com.zsmartsystems.zigbee.sniffer.internal.wireshark;

import java.io.BufferedOutputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;

/**
 * The file has a global header containing some global information followed by zero or more records for each captured
 * packet, looking like this:
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
 * @author Chris Jackson
 *
 */
public class WiresharkPcapFile {
    private BufferedOutputStream output;

    public static int MAGIC_NUMBER_STANDARD = 0xa1b2c3d4;

    public static int LINKTYPE_IEEE802_15_4_WITHFCS = 195;
    public static int LINKTYPE_IEEE802_15_4_NONASK_PHY = 215;
    public static int LINKTYPE_IEEE802_15_4_NOFCS = 230;

    public WiresharkPcapFile(String filename) throws FileNotFoundException, UnsupportedEncodingException {
        output = new BufferedOutputStream(new FileOutputStream(filename));
    }

    public void write(WiresharkPcapFrame frame) {
        try {
            output.write(frame.getBuffer());
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }

    public void close() {
        try {
            output.flush();
            output.close();
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }

    public void write(WiresharkPcapHeader header) {
        header.setVersionMajor(2);
        header.setVersionMinor(4);
        try {
            output.write(header.getBuffer());
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }
}
