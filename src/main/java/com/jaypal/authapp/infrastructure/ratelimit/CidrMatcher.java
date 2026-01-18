package com.jaypal.authapp.infrastructure.ratelimit;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.List;

public final class CidrMatcher {

    private CidrMatcher() {}

    public static boolean matches(String ip, List<String> cidrs) {
        if (ip == null || cidrs == null || cidrs.isEmpty()) {
            return false;
        }

        try {
            InetAddress address = InetAddress.getByName(ip);

            for (String cidr : cidrs) {
                if (cidrMatch(address, cidr)) {
                    return true;
                }
            }

        } catch (UnknownHostException ignored) {
        }

        return false;
    }

    private static boolean cidrMatch(InetAddress address, String cidr)
            throws UnknownHostException {

        String[] parts = cidr.split("/");
        InetAddress network = InetAddress.getByName(parts[0]);
        int prefix = Integer.parseInt(parts[1]);

        byte[] addressBytes = address.getAddress();
        byte[] networkBytes = network.getAddress();

        int fullBytes = prefix / 8;
        int remainingBits = prefix % 8;

        for (int i = 0; i < fullBytes; i++) {
            if (addressBytes[i] != networkBytes[i]) {
                return false;
            }
        }

        if (remainingBits == 0) {
            return true;
        }

        int mask = (-1) << (8 - remainingBits);
        return (addressBytes[fullBytes] & mask)
                == (networkBytes[fullBytes] & mask);
    }
}
