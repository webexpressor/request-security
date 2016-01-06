package com.zhulebei.security.impl;

import java.io.InputStream;

public interface Request<T> {

    String getContentType();

    String getContentLength();

    String getMethod();

    String getRequestUri();

    InputStream getRequestBody();

    T getOriginalRequest();

    void setHeaderValue(String name, String value);

    String getHeaderValue(String name);
}
