package com.zhulebei.http;

import com.zhulebei.security.DefaultRequestSecurity;
import org.apache.http.HttpEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpPut;
import org.apache.http.client.methods.HttpRequestBase;
import org.apache.http.config.Registry;
import org.apache.http.config.RegistryBuilder;
import org.apache.http.conn.socket.ConnectionSocketFactory;
import org.apache.http.conn.socket.LayeredConnectionSocketFactory;
import org.apache.http.conn.socket.PlainConnectionSocketFactory;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.SSLContexts;
import org.apache.http.conn.ssl.TrustStrategy;
import org.apache.http.entity.ByteArrayEntity;
import org.apache.http.entity.ContentType;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.conn.PoolingHttpClientConnectionManager;
import org.apache.http.util.EntityUtils;

import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.nio.charset.Charset;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;

public class HttpUtils {

    private static DefaultRequestSecurity defaultRequestSecurity = null;

    private static CloseableHttpClient httpsClient = null;

    /**
     * 接入方secret key
     */
    private static String SECRET_KEY = "5714bfa80b06424f91fc48678ed2b392";

    private static String KEY = "34d9bc3ca2cf11e591a2525400ae8ce3";

    private static String PRODUCT_NO = "7bc8827e88b5443fa20b8197dab10af2";

    static class AnyTrustStrategy implements TrustStrategy {

        @Override
        public boolean isTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            return true;
        }

    }

    static {
        try {
            RegistryBuilder<ConnectionSocketFactory> registryBuilder = RegistryBuilder.create();
            ConnectionSocketFactory plainSF = new PlainConnectionSocketFactory();
            registryBuilder.register("http", plainSF);

            KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
            SSLContext sslContext =
                    SSLContexts.custom().useTLS().loadTrustMaterial(trustStore, new AnyTrustStrategy()).build();
            LayeredConnectionSocketFactory sslSF =
                    new SSLConnectionSocketFactory(sslContext, SSLConnectionSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER);

            registryBuilder.register("https", sslSF);

            Registry<ConnectionSocketFactory> registry = registryBuilder.build();

            PoolingHttpClientConnectionManager connManager = new PoolingHttpClientConnectionManager(registry);
            connManager.setMaxTotal(500);

            httpsClient = HttpClientBuilder.create().setConnectionManager(connManager).build();

            defaultRequestSecurity = new DefaultRequestSecurity(SECRET_KEY);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static String post(String url, String jsonData, String uId)
            throws IOException, InvalidKeyException, NoSuchAlgorithmException {

        String rs = null;
        HttpPost httppost = new HttpPost(url);

        httppost.setEntity(
                new ByteArrayEntity(jsonData.getBytes(Charset.forName("utf-8")), ContentType.APPLICATION_JSON));

        setCustomHeaders(httppost, uId);

        //进行签名
        defaultRequestSecurity.sign(httppost);

        CloseableHttpResponse response = httpsClient.execute(httppost);
        try {
            HttpEntity entity = response.getEntity();
            if (entity != null) {
                try {
                    rs = EntityUtils.toString(entity, Charset.forName("utf-8"));
                } finally {
                    EntityUtils.consumeQuietly(entity);
                }
            }
        } finally {
            response.close();
            httppost.releaseConnection();
        }

        return rs;
    }

    private static void setCustomHeaders(HttpRequestBase request, String uId) {
        request.setHeader("Key", KEY);
        request.setHeader("ProductNo", PRODUCT_NO);
        request.setHeader("UId", uId);

    }

}
