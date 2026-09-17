package com.example.burpchain;

/** Replaces a byte range without decoding the surrounding HTTP message. */
final class ByteSplice {
    private ByteSplice() {}

    static byte[] replace(byte[] source, int start, int end, byte[] replacement) {
        if (start < 0 || end < start || end > source.length)
            throw new IllegalArgumentException("Selection is outside the request");
        byte[] result = new byte[source.length - (end - start) + replacement.length];
        System.arraycopy(source, 0, result, 0, start);
        System.arraycopy(replacement, 0, result, start, replacement.length);
        System.arraycopy(source, end, result, start + replacement.length, source.length - end);
        return result;
    }
}
