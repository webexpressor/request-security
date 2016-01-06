package com.zhulebei.security;

import org.apache.http.HttpRequest;
import org.apache.http.client.methods.HttpRequestBase;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;

public interface RequestSecurity {

    /**
     * 对 Request 进行签名。
     *
     * @param httpRequest 要签名的 http request 对象
     * @return 签名后的 http request 对象， 请使用这个对象做后续的操作（例如使用 HTTPClient 执行这个 Request）
     * @throws IOException
     * @throws IllegalStateException
     */
    public HttpRequest sign(HttpRequestBase httpRequest) throws IllegalStateException, IOException;

    /**
     * 校验 Request 的签名是否正确
     *
     * @param httpServletRequest 需要校验的 request 实例
     * @return 如果校验未通过，会返回 null。 如果通过则会返回一个新的 HttpServletRequest 实例。后续的操作，需要使用新的 request 实例。 因为校验的过程读取了整个 Request Body。
     * @throws IOException
     */
    public HttpServletRequest verify(HttpServletRequest httpServletRequest) throws IOException;
}
