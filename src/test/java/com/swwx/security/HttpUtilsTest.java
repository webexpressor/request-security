package com.swwx.security;

import com.alibaba.fastjson.JSON;
import com.swwx.http.HttpUtils;
import org.junit.Test;

import java.io.File;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;

/**
 * Created by liudong on 6/1/16.
 */
public class HttpUtilsTest {

    @Test
    public void testPost() throws NoSuchAlgorithmException, InvalidKeyException, IOException {
        Map<String, Object> params = new HashMap<>();
        params.put("name", "张三");
        String uId = "5714bfa80b06424f91fc48678ed2b392";
        Map<String, Object> result = HttpUtils.post("http://localhost:8081/v2/test", JSON.toJSONString(params), uId);
        System.out.println(result);
    }

    @Test
    public void testGet() throws IOException {
        String uId = "5714bfa80b06424f91fc48678ed2b392";
        Map<String, Object> result =
                HttpUtils.httpGet("http://localhost:8081/v2/applies/WPS20151229a001", uId);
        System.out.println(result);
    }

    @Test
    public void testUpload() throws IOException {
        String uId = "5714bfa80b06424f91fc48678ed2b392";
        File file = new File("/Users/dong/workspace/zhulebei-static/download/images/live_weixin.png");
        Map<String, Object> result = HttpUtils.uploadFile("http://localhost:8081/v2/materials/images", file, uId);
        System.out.println(result);
    }
}
