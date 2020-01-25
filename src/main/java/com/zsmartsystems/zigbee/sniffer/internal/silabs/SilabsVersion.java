/**
 * Copyright (c) 2016-2018 by Z-Smart Systems.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 */
package com.zsmartsystems.zigbee.sniffer.internal.silabs;

/**
 * Serialises a the stack version in the Silabs ISD log format
 *
 * @author Chris Jackson
 *
 */
public class SilabsVersion extends SilabsIsdFrame {
    private int[] version;

    public SilabsVersion() {
        packetType = 131138;
        frameType = "ZnetVer";
    }

    public void setVersion(String version) {
        String[] splitVersion = version.split("\\.");

        this.version = new int[4];
        this.version[0] = Integer.parseInt(splitVersion[0]);
        this.version[1] = Integer.parseInt(splitVersion[1]);
        this.version[2] = Integer.parseInt(splitVersion[2]);
        this.version[3] = Integer.parseInt(splitVersion[3]);
    }

    @Override
    public String getBuffer() {
        getHeader();
        formatValue(version[0]);
        formatValue(version[1]);
        formatValue(version[2]);
        formatValue(version[3]);

        formatValue(0);
        formatValue(0);
        formatValue(0);

        return terminateLog();
    }

}
