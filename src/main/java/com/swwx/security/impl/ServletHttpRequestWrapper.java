package com.swwx.security.impl;

import org.apache.commons.io.IOUtils;

import javax.servlet.ServletInputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

public class ServletHttpRequestWrapper implements Request<HttpServletRequest> {

    private final HttpServletRequest originalRequest;

    private final byte[] body;

    public ServletHttpRequestWrapper(HttpServletRequest originalRequest) throws IOException {
        this.originalRequest = originalRequest;
        this.body = IOUtils.toByteArray(originalRequest.getInputStream());
    }

    @Override
    public String getContentType() {
        return this.originalRequest.getContentType();
    }

    @Override
    public String getContentLength() {
        return String.valueOf(body.length);
    }

    @Override
    public String getMethod() {
        return originalRequest.getMethod().toLowerCase();
    }

    @Override
    public String getRequestUri() {
        StringBuilder buf = new StringBuilder();
        buf.append(originalRequest.getRequestURI());

        String queryString = originalRequest.getQueryString();
        if (queryString != null && !"".equals(queryString)) {
            buf.append("?");
            buf.append(queryString);
        }

        return buf.toString();
    }

    @Override
    public InputStream getRequestBody() {
        return new ByteArrayInputStream(body);
    }

    @Override
    public HttpServletRequest getOriginalRequest() {
        final ByteArrayInputStream in = new ByteArrayInputStream(body);
        return new HttpServletRequestWrapper(originalRequest) {

            @Override
            public int getContentLength() {
                return body.length;
            }

            @Override
            public ServletInputStream getInputStream() throws IOException {
                return new ServletInputStream() {

                    @Override
                    public int read() throws IOException {
                        return in.read();
                    }
                };
            }

        };
    }

    @Override
    public void setHeaderValue(String name, String value) {
        throw new RuntimeException("Unsupported operation.");
    }

    @Override
    public String getHeaderValue(String name) {
        return this.originalRequest.getHeader(name);
    }
}
