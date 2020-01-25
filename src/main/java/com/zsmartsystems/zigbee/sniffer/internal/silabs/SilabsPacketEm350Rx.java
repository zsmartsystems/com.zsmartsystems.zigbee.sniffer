/**
 * Copyright (c) 2016-2018 by Z-Smart Systems.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 */
package com.zsmartsystems.zigbee.sniffer.internal.silabs;

/**
 * Serialises a data packet from an EM350 to the Silabs ISD log format
 *
 * @author Chris Jackson
 *
 */
public class SilabsPacketEm350Rx extends SilabsIsdFrame {
    private int[] data;
    private int lqi;
    private int rssi;
    private int channel;

    public SilabsPacketEm350Rx() {
        packetType = 16908325;
        frameType = "Packet";
    }

    public void setData(int[] data) {
        this.data = data;
    }

    public void setLqi(int lqi) {
        this.lqi = lqi;
    }

    public void setRssi(int rssi) {
        this.rssi = rssi;
    }

    public void setChannel(int channel) {
        this.channel = channel;
    }

    @Override
    public String getBuffer() {
        // 32uS per byte - extra bytes added to give same value as Simplicity Studio generated logs.
        eventDuration = (data.length + 9) * 32;

        getHeader();
        formatValue(data.length);
        for (int value : data) {
            formatValue(value);
        }

        formatValue(lqi);
        formatValue(rssi);
        formatValue((channel - 11) * 16);

        return terminateLog();
    }

}
