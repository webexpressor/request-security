package com.swwx.security.impl;

import org.apache.commons.io.IOUtils;
import org.apache.http.Header;
import org.apache.http.HttpEntity;
import org.apache.http.HttpEntityEnclosingRequest;
import org.apache.http.HttpRequest;
import org.apache.http.client.methods.HttpRequestBase;
import org.apache.http.entity.ByteArrayEntity;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;

public class HttpComponentRequestWrapper implements Request<HttpRequest> {

    private final HttpRequestBase originalRequest;

    private byte[] body;

    private String contentType;

    private String contentLength;

    public HttpComponentRequestWrapper(HttpRequestBase originalRequest) throws IllegalStateException, IOException {
        this.originalRequest = originalRequest;
        HttpEntity entity = null;
        if (originalRequest instanceof HttpEntityEnclosingRequest
                && (entity = ((HttpEntityEnclosingRequest)originalRequest).getEntity()) != null) {

            contentType = entity.getContentType() == null ? "" : entity.getContentType().getValue();

            if (contentType.indexOf("multipart/form-data") != -1) {
                body = new byte[0];
            }else{
                body = IOUtils.toByteArray(entity.getContent());

                ByteArrayEntity newEntity = new ByteArrayEntity(body);
                newEntity.setContentType(entity.getContentType());
                ((HttpEntityEnclosingRequest)originalRequest).setEntity(newEntity);
            }

            contentLength = String.valueOf(body.length);
        }
    }

    @Override
    public String getContentType() {
        return this.contentType;
    }

    @Override
    public String getContentLength() {
        return this.contentLength;
    }

    @Override
    public String getMethod() {
        return originalRequest.getRequestLine().getMethod().toLowerCase();
    }

    @Override
    public String getRequestUri() {
        StringBuilder buf = new StringBuilder();

        URI uri = this.originalRequest.getURI();
        buf.append(uri.getPath());

        String queryString = uri.getQuery();
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
    public HttpRequest getOriginalRequest() {
        return originalRequest;
    }

    @Override
    public void setHeaderValue(String name, String value) {
        originalRequest.setHeader(name, value);
    }

    @Override
    public String getHeaderValue(String name) {
        Header header = this.originalRequest.getFirstHeader(name);
        if (header == null) {
            return "";
        } else {
            return header.getValue();
        }
    }
}
