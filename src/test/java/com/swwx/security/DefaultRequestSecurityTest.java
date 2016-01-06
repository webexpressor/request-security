package com.swwx.security;

import org.apache.commons.codec.binary.Base64;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ByteArrayEntity;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Controller;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.Assert.*;

@WebAppConfiguration
public class DefaultRequestSecurityTest {

    private DefaultRequestSecurity rs = null;
    private SecretKey key = null;

    private static final Pattern NONCE = Pattern
            .compile("\\s*nonce\\s*=\\s*([^,]+)\\s*");
    private static final Pattern TIMESTAMP = Pattern
            .compile("\\s*timestamp\\s*=\\s*([^,]+)\\s*");
    private static final Pattern SIGNATURE = Pattern
            .compile("\\s*signature\\s*=\\s*([^,]+)\\s*");

    @Before
    public void setup() throws Exception {
        key = new SecretKeySpec("1234567890123456".getBytes(), "HmacSHA256");
        rs = new DefaultRequestSecurity(
                Base64.encodeBase64String("1234567890123456".getBytes()));
    }

    @Test
    public void testSignGet() throws Exception {
        HttpGet get = new HttpGet("https://abc.com/query?a=b");
        rs.sign(get);

        assertNotNull(get.getFirstHeader(DefaultRequestSecurity.HEADER_NAME));

        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(key);

        String signatureHeader = get.getFirstHeader(
                DefaultRequestSecurity.HEADER_NAME).getValue();

        mac.update(getNonce(signatureHeader).getBytes());
        mac.update("\n".getBytes());
        mac.update(getTimestamp(signatureHeader).getBytes());
        mac.update("\n".getBytes());
        mac.update("get\n".getBytes());
        mac.update("https://abc.com/query?a=b\n".getBytes());
        mac.update("\n".getBytes());
        mac.update("\n".getBytes());
        mac.update("".getBytes());
        byte[] expected = mac.doFinal();

        assertArrayEquals(expected, getSignature(signatureHeader));
    }

    @Test
    public void testSignPost() throws InvalidKeyException,
            NoSuchAlgorithmException, IllegalStateException, IOException {
        HttpPost post = new HttpPost("https://abc.com/create?a=b");
        ByteArrayEntity entity = new ByteArrayEntity("abcdefg".getBytes());
        entity.setContentType("plain/text");
        post.setEntity(entity);

        rs.sign(post);

        assertNotNull(post.getFirstHeader(DefaultRequestSecurity.HEADER_NAME));

        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(key);

        String signatureHeader = post.getFirstHeader(
                DefaultRequestSecurity.HEADER_NAME).getValue();

        mac.update(getNonce(signatureHeader).getBytes());
        mac.update("\n".getBytes());
        mac.update(getTimestamp(signatureHeader).getBytes());
        mac.update("\n".getBytes());
        mac.update("post\n".getBytes());
        mac.update("https://abc.com/create?a=b\n".getBytes());
        mac.update("plain/text\n".getBytes());
        mac.update("7\n".getBytes());
        mac.update("abcdefg".getBytes());
        byte[] expected = mac.doFinal();

        assertArrayEquals(expected, getSignature(signatureHeader));

    }

    private String getTimestamp(String header) {
        Matcher m = TIMESTAMP.matcher(header);
        if (m.find()) {
            return m.group(1);
        } else {
            return null;
        }
    }

    private byte[] getSignature(String header) {
        Matcher m = SIGNATURE.matcher(header);
        if (m.find()) {
            return Base64.decodeBase64(m.group(1));
        } else {
            return null;
        }
    }

    private String getNonce(String header) {
        Matcher m = NONCE.matcher(header);
        if (m.find()) {
            return m.group(1);
        } else {
            return null;
        }
    }

    @Test
    public void testSuccessVerify() throws Exception {
        assertNotNull(verify("Hello,World!"));
    }

    @Test
    public void testVerifyFailedWhenTheseIsNHeader() throws Exception {
        HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
        final InputStream bodyInput = new ByteArrayInputStream("123123".getBytes());

        Mockito.when(request.getInputStream()).thenReturn(
                new ServletInputStream() {

                    @Override
                    public int read() throws IOException {
                        return bodyInput.read();
                    }
                });
        assertNull(rs.verify(request));
    }

    public HttpServletRequest verify(String requestBody) throws Exception {
        HttpServletRequest request = Mockito.mock(HttpServletRequest.class);
        final byte[] body = requestBody.getBytes();
        final InputStream bodyInput = new ByteArrayInputStream(body);
        Mockito.when(request.getInputStream()).thenReturn(
                new ServletInputStream() {

                    @Override
                    public int read() throws IOException {
                        return bodyInput.read();
                    }
                });

        Mockito.when(request.getContentType()).thenReturn("plain/text");
        Mockito.when(request.getContentLength()).thenReturn(body.length);
        Mockito.when(
                request.getHeader(Mockito
                        .eq(DefaultRequestSecurity.HEADER_NAME)))
                .thenReturn(
                        "Key nonce=97a38e5ba26a3ef4185626bb69d1534912c407815e6fea3438fd9a7b2fe08998,timestamp=1434095867279,signature=fuvh2+vywF9wqIW7IRPdqDAyJVd8fXntkmUlA62+im4=");
        Mockito.when(request.getMethod()).thenReturn("POST");
        Mockito.when(request.getScheme()).thenReturn("Https");
        Mockito.when(request.getServerName()).thenReturn("a.com");
        Mockito.when(request.getRequestURI()).thenReturn("/b");
        Mockito.when(request.getQueryString()).thenReturn("query=c");

        return rs.verify(request);
    }

    @Test
    public void testBodyCasedVerifyFailed() throws Exception {
        assertNull(verify("Bad Message."));
    }

    @Test
    public void testVerify() throws Exception {
        MockMvc mockMvc = MockMvcBuilders.standaloneSetup(new TestController())
                .addFilter(new TestFilter(rs), "/*").build();

        String nonce = "abcdefg";
        String timestamp = "112223344";
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(key);
        String signature = Base64
                .encodeBase64String(mac
                        .doFinal((nonce + "\n" + timestamp + "\npost\nhttps://a.com/b?query=c\napplication/x-www-form-urlencoded\n7\nfield=x")
                                .getBytes()));

        mockMvc.perform(MockMvcRequestBuilders
                .post("https://a.com/b?query=c")
                .header("X-Money-Signature",
                        "nonce=" + nonce + ",timestamp=" + timestamp
                                + ",signature=" + signature).content("field=x")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED));

    }

    @Controller
    private static class TestController {
        @RequestMapping(value = "/b", method = RequestMethod.POST)
        public void action(@RequestParam("field") String field,
                           @RequestParam("query") String query) {
            assertEquals("x", field);
            assertEquals("c", query);
        }
    }

    private static class TestFilter implements Filter {
        public TestFilter(RequestSecurity rs) {
            this.rs = rs;
        }

        @Override
        public void init(FilterConfig filterConfig) throws ServletException {
        }

        @Override
        public void destroy() {
        }

        private RequestSecurity rs;

        @Override
        public void doFilter(ServletRequest request, ServletResponse response,
                             FilterChain chain) throws IOException, ServletException {
            HttpServletRequest req = this.rs
                    .verify((HttpServletRequest) request);

            assertNotNull(req);
            chain.doFilter(req, response);
        }
    }
}
