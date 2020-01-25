/**
 * Copyright (c) 2016-2018 by Z-Smart Systems.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 */
package com.zsmartsystems.zigbee.sniffer.internal.silabs;

import java.io.FileNotFoundException;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;

/**
 * This class provides a logger in the Silabs ISD event.log format
 *
 * @author Chris Jackson
 *
 */
public class SilabsIsdLogFile {
    private final PrintWriter writer;

    public SilabsIsdLogFile(String filename) throws FileNotFoundException, UnsupportedEncodingException {
        writer = new PrintWriter(filename, "UTF-8");

        writer.println("# (c) Ember - InSight Desktop");
        writer.println("# File created with Z-Smart Systems ZigBeeSniffer");
        writer.flush();
    }

    public void write(SilabsIsdFrame frame) {
        writer.println(frame.getBuffer());
        writer.flush();
    }

    public void close() {
        writer.flush();
        writer.close();
    }
}
