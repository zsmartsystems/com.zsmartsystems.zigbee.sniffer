/**
 * Copyright (c) 2016-2018 by Z-Smart Systems.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 */
package com.zsmartsystems.zigbee.sniffer.internal;

import java.util.Arrays;

public abstract class ZigBeeSnifferBinaryFrame {
    protected byte[] buffer = new byte[180];
    protected int length = 0;

    protected int[] data;

    public void setData(int[] data) {
        this.data = Arrays.copyOf(data, data.length);
    }

    protected void serializeBoolean(boolean val) {
        buffer[length++] = (byte) (val ? 0x01 : 0x00);
    }

    protected void serializeInt8(int val) {
        buffer[length++] = (byte) (val & 0xFF);
    }

    protected void serializeInt16(int val) {
        buffer[length++] = (byte) ((val >> 8) & 0xFF);
        buffer[length++] = (byte) (val & 0xFF);
    }

    protected void serializeInt32(int val) {
        buffer[length++] = (byte) ((val >> 24) & 0xFF);
        buffer[length++] = (byte) ((val >> 16) & 0xFF);
        buffer[length++] = (byte) ((val >> 8) & 0xFF);
        buffer[length++] = (byte) (val & 0xFF);
    }

    protected void serializeLong(long val) {
        buffer[length++] = (byte) ((val >> 56) & 0xFF);
        buffer[length++] = (byte) ((val >> 48) & 0xFF);
        buffer[length++] = (byte) ((val >> 40) & 0xFF);
        buffer[length++] = (byte) ((val >> 32) & 0xFF);
        buffer[length++] = (byte) ((val >> 24) & 0xFF);
        buffer[length++] = (byte) ((val >> 16) & 0xFF);
        buffer[length++] = (byte) ((val >> 8) & 0xFF);
        buffer[length++] = (byte) (val & 0xFF);
    }

    protected void serializeData(int[] valArray) {
        for (int valByte : valArray) {
            buffer[length++] = (byte) valByte;
        }
    }

}
