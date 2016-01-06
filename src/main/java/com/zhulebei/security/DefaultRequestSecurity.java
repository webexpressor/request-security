package com.zhulebei.security;

import com.zhulebei.security.impl.HttpComponentRequestWrapper;
import com.zhulebei.security.impl.Request;
import com.zhulebei.security.impl.ServletHttpRequestWrapper;
import com.zhulebei.security.impl.Signature;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.io.IOUtils;
import org.apache.http.HttpRequest;
import org.apache.http.client.methods.HttpRequestBase;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.http.HttpServletRequest;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.Charset;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/**
 * 默认的 Request 签名校验实现。 采用了 HmacSHA256 算法对 Request 的
 * Method\URI\Content-Type\Content-Length\Body 进行签名 使用时，请确保处理的 Request Body
 * 不会太大。由于需要对 Request Body 进行签名。所以需要在内存中缓存整个 Request Body.如果 Body 太大（例如超过 1G），
 * 可能会引起系统的 OOM 错误。
 */
public class DefaultRequestSecurity implements RequestSecurity {

    private final SecretKey secretKey;

    private static final String ALGORITHM = "HmacSHA256";

    static final String HEADER_NAME = "Authorization";

    private final SecureRandom random = new SecureRandom();

    private final Charset DEFAULT_CHARSET = Charset.forName("utf-8");

    private final int NONCE_LENGTH = 8;

    public DefaultRequestSecurity(String secretKey) throws NoSuchAlgorithmException, InvalidKeyException {
        this.secretKey = new SecretKeySpec(Base64.decodeBase64(secretKey), ALGORITHM);
        Mac mac = Mac.getInstance(ALGORITHM);
        mac.init(this.secretKey);
    }

    @Override
    public HttpRequest sign(HttpRequestBase httpRequest) throws IllegalStateException, IOException {
        Request<HttpRequest> request = new HttpComponentRequestWrapper(httpRequest);
        byte[] buf = new byte[NONCE_LENGTH];
        random.nextBytes(buf);
        String nonce = Hex.encodeHexString(buf);
        String timestamp = String.valueOf(System.currentTimeMillis());

        byte[] baseString = buildBaseString(request, nonce, timestamp);

        try {
            Mac mac = Mac.getInstance(ALGORITHM);
            mac.init(secretKey);
            String signatureValue = Base64.encodeBase64String(mac.doFinal(baseString));
            request.setHeaderValue(HEADER_NAME, "Key " + new Signature(nonce, timestamp, signatureValue).toString());
            return request.getOriginalRequest();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeyException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public HttpServletRequest verify(HttpServletRequest httpServletRequest) throws IOException {
        Request<HttpServletRequest> request = new ServletHttpRequestWrapper(httpServletRequest);
        String authorization = request.getHeaderValue(HEADER_NAME);
        Signature signature = Signature.parseFromHeader(authorization.split(" ")[1]);
        if (signature == null) {
            return null;
        }

        byte[] baseString = buildBaseString(request, signature.getNonce(), signature.getTimestamp());

        try {
            Mac mac = Mac.getInstance(ALGORITHM);
            mac.init(secretKey);
            String signatureValue = Base64.encodeBase64String(mac.doFinal(baseString));
            if (signatureValue.equals(signature.getSign())) {
                return request.getOriginalRequest();
            } else {
                return null;
            }
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeyException e) {
            throw new RuntimeException(e);
        }
    }

    private byte[] buildBaseString(Request<?> request, String nonce, String timestamp) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(nonce.getBytes(DEFAULT_CHARSET));
        System.out.println("nonce=" + nonce);
        out.write('\n');
        out.write(timestamp.getBytes(DEFAULT_CHARSET));
        System.out.println("timestamp=" + timestamp);
        out.write('\n');
        out.write(request.getMethod().toLowerCase().getBytes(DEFAULT_CHARSET));
        System.out.println("request method=" + request.getMethod().toLowerCase());
        out.write('\n');
        out.write(request.getRequestUri().getBytes(DEFAULT_CHARSET));
        System.out.println("request uri=" + request.getRequestUri());
        out.write('\n');

        //如果content-type为multipart/form-data，以下内容不进行签名
        if (request.getContentType() != null
                && request.getContentType().indexOf("multipart/form-data") == -1) {
            out.write(request.getContentType().toLowerCase().getBytes(DEFAULT_CHARSET));
            System.out.println("content type=" + request.getContentType().toLowerCase());
            out.write('\n');
            out.write(request.getContentLength().getBytes(DEFAULT_CHARSET));
            System.out.println("content length=" + request.getContentLength());
            out.write('\n');
            byte []data = IOUtils.toByteArray(request.getRequestBody());
            System.out.println("request body=" + new String(data));
            out.write(data);
        }

        out.close();
        return out.toByteArray();
    }

}
