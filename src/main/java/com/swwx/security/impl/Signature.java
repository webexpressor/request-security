package com.swwx.security.impl;

import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class Signature {

    private static final Pattern NVP = Pattern.compile("([^=]+)\\s*=\\s*\"?(\\S*)\"?");

    String nonce;

    String timestamp;

    String sign;

    public static Signature parseFromHeader(String headerValue) {
        Map<String, String> result = new HashMap<String, String>();
        Signature signature = null;
        if (headerValue != null) {
            for (String param : headerValue.split("\\s*,\\s*")) {
                Matcher m = NVP.matcher(param);
                if (m.matches()) {
                    result.put(m.group(1), m.group(2));
                }
            }

            signature = new Signature(result.get("nonce"), result.get("timestamp"), result.get("signature"));
        }
        if (signature == null || isBlank(signature.nonce) || isBlank(signature.timestamp) || isBlank(signature.sign)) {
            return null;
        } else {
            return signature;
        }
    }

    public Signature(String nonce, String timestamp, String sign) {
        this.nonce = nonce;
        this.timestamp = timestamp;
        this.sign = sign;
    }

    @Override
    public String toString() {
        StringBuilder buf = new StringBuilder();
        buf.append("nonce=");
        buf.append(this.nonce);
        buf.append(",timestamp=");
        buf.append(this.timestamp);
        buf.append(",signature=");
        buf.append(this.sign);
        return buf.toString();
    }

    public String getNonce() {
        return nonce;
    }

    public String getTimestamp() {
        return timestamp;
    }

    public String getSign() {
        return sign;
    }

    private static boolean isBlank(String value) {
        return value == null || value.trim().length() <= 0;
    }

}