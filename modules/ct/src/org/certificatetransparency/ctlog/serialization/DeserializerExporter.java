package org.certificatetransparency.ctlog.serialization;

import java.io.InputStream;

/**
 * Just to expose package-private {@link Deserializer#readVariableLength}.
 */
public class DeserializerExporter {

    public static byte[] readVariableLength(InputStream inputStream, int maxDataLength) {
        return Deserializer.readVariableLength(inputStream, maxDataLength);
    }
}
