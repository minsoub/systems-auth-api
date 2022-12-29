package com.bithumbsystems.auth.core.util;

import java.net.InetAddress;
import java.net.UnknownHostException;


import org.springframework.util.Assert;
import org.springframework.util.StringUtils;


public final class IpAddressMatcher {

    private final int nMaskBits;

    private final InetAddress requiredAddress;

    /**
     * Takes a specific IP address or a range specified using the IP/Netmask (e.g.
     * 192.168.1.0/24 or 202.24.0.0/14).
     * @param ipAddress the address or range of addresses from which the request must
     * come.
     */
    public IpAddressMatcher(String ipAddress) {
        if (ipAddress.indexOf('/') > 0) {
            String[] addressAndMask = StringUtils.split(ipAddress, "/");
            ipAddress = addressAndMask[0];
            this.nMaskBits = Integer.parseInt(addressAndMask[1]);
        }
        else {
            this.nMaskBits = -1;
        }
        this.requiredAddress = parseAddress(ipAddress);
        Assert.isTrue(this.requiredAddress.getAddress().length * 8 >= this.nMaskBits,
                String.format("IP address %s is too short for bitmask of length %d", ipAddress, this.nMaskBits));
    }

    public boolean matches(String address) {
        InetAddress remoteAddress = parseAddress(address);
        if (!this.requiredAddress.getClass().equals(remoteAddress.getClass())) {
            return false;
        }
        if (this.nMaskBits < 0) {
            return remoteAddress.equals(this.requiredAddress);
        }
        byte[] remAddr = remoteAddress.getAddress();
        byte[] reqAddr = this.requiredAddress.getAddress();
        int nMaskFullBytes = this.nMaskBits / 8;
        byte finalByte = (byte) (0xFF00 >> (this.nMaskBits & 0x07));
        for (int i = 0; i < nMaskFullBytes; i++) {
            if (remAddr[i] != reqAddr[i]) {
                return false;
            }
        }
        if (finalByte != 0) {
            return (remAddr[nMaskFullBytes] & finalByte) == (reqAddr[nMaskFullBytes] & finalByte);
        }
        return true;
    }

    private InetAddress parseAddress(String address) {
        try {
            return InetAddress.getByName(address);
        }
        catch (UnknownHostException ex) {
            throw new IllegalArgumentException("Failed to parse address" + address, ex);
        }
    }

}
