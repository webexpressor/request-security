package com.swwx.security.impl;

import org.apache.http.HttpEntity;
import org.apache.http.HttpRequest;
import org.apache.http.client.methods.HttpEntityEnclosingRequestBase;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.util.EntityUtils;
import org.junit.Test;

import java.io.IOException;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

public class HttpComponentRequestWrapperTest {


    @Test
    public void testWrappedRequestBodyShouldBeAvailable() throws IllegalStateException, IOException {
        HttpPost post = new HttpPost("https://a.com/b?query=c");
        StringEntity entity = new StringEntity("Hello, World!");
        entity.setContentType("application/text");
        post.setEntity(entity);

        HttpComponentRequestWrapper w = new HttpComponentRequestWrapper(post);
        HttpRequest actual = w.getOriginalRequest();

        assertEquals("post", actual.getRequestLine().getMethod().toLowerCase());
        HttpEntity actualEntity = ((HttpEntityEnclosingRequestBase) actual).getEntity();

        assertNotNull(actualEntity);
        assertEquals("application/text", actualEntity.getContentType().getValue());
        assertEquals(13, actualEntity.getContentLength());
        assertEquals("https://a.com/b?query=c", actual.getRequestLine().getUri());
        assertEquals("Hello, World!", EntityUtils.toString(actualEntity));
    }

}
