package com.swwx.http;

import com.swwx.security.DefaultRequestSecurity;
import org.apache.http.HttpEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
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
import org.apache.http.entity.mime.MultipartEntityBuilder;
import org.apache.http.entity.mime.content.FileBody;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.conn.PoolingHttpClientConnectionManager;
import org.apache.http.util.EntityUtils;

import javax.net.ssl.SSLContext;
import java.io.File;
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

    public static Map<String, Object> post(String url, String jsonData, String uId)
            throws IOException, InvalidKeyException, NoSuchAlgorithmException {
        Map<String, Object> result = new HashMap<>();

        HttpPost httpPost = new HttpPost(url);

        httpPost.setEntity(
                new ByteArrayEntity(jsonData.getBytes(Charset.forName("utf-8")), ContentType.APPLICATION_JSON));

        setCustomHeaders(httpPost, uId);

        //进行签名
        defaultRequestSecurity.sign(httpPost);

        CloseableHttpResponse response = httpsClient.execute(httpPost);
        try {
            HttpEntity entity = response.getEntity();
            if (entity != null) {
                try {
                    result.put("code", response.getStatusLine().getStatusCode());
                    result.put("data", EntityUtils.toString(entity, Charset.forName("utf-8")));
                } finally {
                    EntityUtils.consumeQuietly(entity);
                }
            }
        } finally {
            response.close();
            httpPost.releaseConnection();
        }

        return result;
    }

    public static Map<String, Object> httpGet(String url, String uId) throws IOException {
        Map<String, Object> result = new HashMap<>();

        HttpGet httpGet = new HttpGet(url);

        setCustomHeaders(httpGet, uId);

        //进行签名
        defaultRequestSecurity.sign(httpGet);

        CloseableHttpResponse response = httpsClient.execute(httpGet);
        try {
            HttpEntity entity = response.getEntity();
            if (entity != null) {
                try {
                    result.put("code", response.getStatusLine().getStatusCode());
                    result.put("data", EntityUtils.toString(entity, Charset.forName("utf-8")));
                } finally {
                    EntityUtils.consumeQuietly(entity);
                }
            }
        } finally {
            response.close();
            httpGet.releaseConnection();
        }

        return result;
    }

    public static Map<String, Object> uploadFile(String url, File file, String uId) throws IOException {
        Map<String, Object> result = new HashMap<>();

        HttpPost httpPost = new HttpPost(url);

        FileBody fileBody = new FileBody(file);
        HttpEntity httpEntity = MultipartEntityBuilder.create().addPart("file", fileBody).build();

        httpPost.setEntity(httpEntity);

        setCustomHeaders(httpPost, uId);

        //进行签名
        defaultRequestSecurity.sign(httpPost);

        CloseableHttpResponse response = httpsClient.execute(httpPost);
        try {
            HttpEntity entity = response.getEntity();
            if (entity != null) {
                try {
                    result.put("code", response.getStatusLine().getStatusCode());
                    result.put("data", EntityUtils.toString(entity, Charset.forName("utf-8")));
                } finally {
                    EntityUtils.consumeQuietly(entity);
                }
            }
        } finally {
            response.close();
            httpPost.releaseConnection();
        }

        return result;
    }

    private static void setCustomHeaders(HttpRequestBase request, String uId) {
        request.setHeader("Key", KEY); //公钥
        request.setHeader("ProductNo", PRODUCT_NO); //产品唯一标识
        request.setHeader("UId", uId); //第三方用户唯一标识
    }

}
