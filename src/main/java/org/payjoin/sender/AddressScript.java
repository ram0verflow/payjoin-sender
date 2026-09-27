package org.payjoin.sender;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/** Bitcoin address to scriptPubKey. Bech32, bech32m, and base58. */
final class AddressScript {
    private static final String CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    private static final String BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    private static final int BECH32 = 1;
    private static final int BECH32M = 0x2bc830a3;

    private AddressScript() {}

    static byte[] script(String address) {
        if (address == null || address.isEmpty()) {
            throw new IllegalArgumentException("address is required");
        }
        int separator = address.lastIndexOf('1');
        if (separator > 0) {
            String hrp = address.substring(0, separator);
            if (hrp.equalsIgnoreCase("bc") || hrp.equalsIgnoreCase("tb") || hrp.equalsIgnoreCase("bcrt")) {
                return witness(address, separator);
            }
        }
        return base58(address);
    }

    private static byte[] witness(String address, int separator) {
        boolean lower = address.toLowerCase(java.util.Locale.ROOT).equals(address);
        boolean upper = address.toUpperCase(java.util.Locale.ROOT).equals(address);
        if (!lower && !upper) {
            throw new IllegalArgumentException("address mixes case");
        }
        String hrp = address.substring(0, separator).toLowerCase(java.util.Locale.ROOT);
        String dataPart = address.substring(separator + 1).toLowerCase(java.util.Locale.ROOT);
        if (dataPart.length() < 6) {
            throw new IllegalArgumentException("address is too short");
        }
        int[] data = new int[dataPart.length()];
        for (int i = 0; i < dataPart.length(); i++) {
            int value = CHARSET.indexOf(dataPart.charAt(i));
            if (value < 0) {
                throw new IllegalArgumentException("address is not bech32");
            }
            data[i] = value;
        }
        int version = data[0];
        if (version > 16) {
            throw new IllegalArgumentException("address witness version is invalid");
        }
        int constant = version == 0 ? BECH32 : BECH32M;
        if (polymod(hrp, data) != constant) {
            throw new IllegalArgumentException("address checksum is invalid");
        }
        int[] programData = new int[data.length - 7];
        System.arraycopy(data, 1, programData, 0, programData.length);
        byte[] program = convert(programData);
        if (version == 0 && program.length != 20 && program.length != 32) {
            throw new IllegalArgumentException("address witness program length is invalid");
        }
        if (program.length < 2 || program.length > 40) {
            throw new IllegalArgumentException("address witness program length is invalid");
        }
        byte[] script = new byte[2 + program.length];
        script[0] = version == 0 ? 0x00 : (byte) (0x50 + version);
        script[1] = (byte) program.length;
        System.arraycopy(program, 0, script, 2, program.length);
        return script;
    }

    private static byte[] convert(int[] data) {
        int accumulator = 0;
        int bits = 0;
        byte[] out = new byte[data.length * 5 / 8];
        int written = 0;
        for (int value : data) {
            accumulator = (accumulator << 5) | value;
            bits += 5;
            while (bits >= 8) {
                bits -= 8;
                out[written++] = (byte) ((accumulator >> bits) & 0xff);
            }
        }
        if (bits >= 5 || (bits > 0 && ((accumulator << (8 - bits)) & 0xff) != 0)) {
            throw new IllegalArgumentException("address padding is invalid");
        }
        if (written != out.length) {
            throw new IllegalArgumentException("address padding is invalid");
        }
        return out;
    }

    private static int polymod(String hrp, int[] data) {
        int[] values = new int[hrp.length() * 2 + 1 + data.length];
        int index = 0;
        for (int i = 0; i < hrp.length(); i++) {
            values[index++] = hrp.charAt(i) >> 5;
        }
        values[index++] = 0;
        for (int i = 0; i < hrp.length(); i++) {
            values[index++] = hrp.charAt(i) & 31;
        }
        for (int value : data) {
            values[index++] = value;
        }
        int checksum = 1;
        for (int value : values) {
            int top = checksum >>> 25;
            checksum = ((checksum & 0x1ffffff) << 5) ^ value;
            if ((top & 1) != 0) {
                checksum ^= 0x3b6a57b2;
            }
            if ((top & 2) != 0) {
                checksum ^= 0x26508e6d;
            }
            if ((top & 4) != 0) {
                checksum ^= 0x1ea119fa;
            }
            if ((top & 8) != 0) {
                checksum ^= 0x3d4233dd;
            }
            if ((top & 16) != 0) {
                checksum ^= 0x2a1462b3;
            }
        }
        return checksum;
    }

    private static byte[] base58(String address) {
        if (address.isEmpty()) {
            throw new IllegalArgumentException("address is required");
        }
        BigInteger value = BigInteger.ZERO;
        for (int i = 0; i < address.length(); i++) {
            int digit = BASE58.indexOf(address.charAt(i));
            if (digit < 0) {
                throw new IllegalArgumentException("address is not base58");
            }
            value = value.multiply(BigInteger.valueOf(58)).add(BigInteger.valueOf(digit));
        }
        byte[] body = value.toByteArray();
        int zeros = 0;
        while (zeros < address.length() && address.charAt(zeros) == '1') {
            zeros++;
        }
        if (body.length > 0 && body[0] == 0) {
            body = java.util.Arrays.copyOfRange(body, 1, body.length);
        }
        byte[] raw = new byte[zeros + body.length];
        System.arraycopy(body, 0, raw, zeros, body.length);
        if (raw.length != 25) {
            throw new IllegalArgumentException("address has the wrong length");
        }
        byte[] payload = java.util.Arrays.copyOf(raw, 21);
        byte[] checksum = hash256(payload);
        for (int i = 0; i < 4; i++) {
            if (checksum[i] != raw[21 + i]) {
                throw new IllegalArgumentException("address checksum is invalid");
            }
        }
        byte[] hash = java.util.Arrays.copyOfRange(payload, 1, 21);
        if (payload[0] == 0x00 || payload[0] == 0x6f) {
            return p2pkh(hash);
        }
        if (payload[0] == 0x05 || payload[0] == (byte) 0xc4) {
            return p2sh(hash);
        }
        throw new IllegalArgumentException("address version is not a supported script");
    }

    private static byte[] p2pkh(byte[] hash) {
        byte[] script = new byte[25];
        script[0] = 0x76;
        script[1] = (byte) 0xa9;
        script[2] = 20;
        System.arraycopy(hash, 0, script, 3, 20);
        script[23] = (byte) 0x88;
        script[24] = (byte) 0xac;
        return script;
    }

    private static byte[] p2sh(byte[] hash) {
        byte[] script = new byte[23];
        script[0] = (byte) 0xa9;
        script[1] = 20;
        System.arraycopy(hash, 0, script, 2, 20);
        script[22] = (byte) 0x87;
        return script;
    }

    private static byte[] hash256(byte[] data) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return digest.digest(digest.digest(data));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
