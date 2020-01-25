/**
 * Copyright (c) 2016-2018 by Z-Smart Systems.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 */
package com.zsmartsystems.zigbee.sniffer.internal.silabs;

import com.zsmartsystems.zigbee.IeeeAddress;

/**
 * Serialises an adapter in the Silabs ISD log format
 *
 * @author Chris Jackson
 *
 */
public class SilabsAdapter extends SilabsIsdFrame {
    private IeeeAddress address;

    public SilabsAdapter() {
        packetType = 327686;
        frameType = "Adapter";
    }

    public void setAddress(IeeeAddress address) {
        this.address = address;
    }

    @Override
    public String getBuffer() {
        getHeader();
        formatValue(address.getValue()[7]);
        formatValue(address.getValue()[6]);
        formatValue(address.getValue()[5]);
        formatValue(address.getValue()[4]);
        formatValue(address.getValue()[3]);
        formatValue(address.getValue()[2]);
        formatValue(address.getValue()[1]);
        formatValue(address.getValue()[0]);

        return terminateLog();
    }

}
