/**
 * Copyright (c) 2016-2018 by Z-Smart Systems.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 */
package com.zsmartsystems.zigbee.sniffer.internal.silabs;

/**
 * Serialises an Printf statement in the Silabs ISD log format
 *
 * @author Chris Jackson
 *
 */
public class SilabsPrintf extends SilabsIsdFrame {
    private String string;

    public SilabsPrintf() {
        packetType = 131074;
        frameType = "Printf";
    }

    public void setString(String string) {
        this.string = string;
    }

    @Override
    public String getBuffer() {
        getHeader();
        for (char value : string.toCharArray()) {
            formatValue(Integer.valueOf(value));
        }

        return terminateLog();
    }

}
