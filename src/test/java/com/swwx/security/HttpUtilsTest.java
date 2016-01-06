package com.swwx.security;

import com.alibaba.fastjson.JSON;
import com.swwx.http.HttpUtils;
import org.junit.Before;
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

    private String uId;

    @Before
    public void before() {
        uId = "5714bfa80b06424f91fc48678ed2b392";
    }

    @Test
    public void testPost() throws NoSuchAlgorithmException, InvalidKeyException, IOException {
        Map<String, Object> params = new HashMap<>();
        params.put("name", "张三");
        Map<String, Object> result = HttpUtils.post("http://172.30.21.6:9000/v2/test", JSON.toJSONString(params), uId);
        System.out.println(result);
    }

    @Test
    public void testSaveMaterial() throws NoSuchAlgorithmException, InvalidKeyException, IOException {
        String jsonStr =
                "{\"idcards\":{\"idcardHand\":{\"serverId\":\"dceeeee7-68a2-4b13-ab5a-c6780db6c8b4\"},\"idcardBack\":{\"serverId\":\"67515d8e-58ae-4769-ade2-74670b5c81c4\"},\"idcardFront\":{\"serverId\":\"ad27bd38-a841-4aa3-8220-a795ba8a09df\"}},\"contacts\":[{\"contactPhone\":\"13211111111\",\"contactName\":\"张三\",\"contactType\":\"CLASSMATE\"}]}";

        Map<String, Object> result = HttpUtils.post("http://172.30.21.6:9000/v2/materials", jsonStr, uId);

        System.out.println(result);
    }

    @Test
    public void testGet() throws IOException {
        Map<String, Object> result =
                HttpUtils.httpGet("http://172.30.21.6:9000/v2/applies/WPS20151229a001", uId);
        System.out.println(result);
    }

    @Test
    public void testUpload() throws IOException {
        File file = new File("/Users/dong/workspace/zhulebei-static/download/images/live_weixin.png");
        Map<String, Object> result = HttpUtils.uploadFile("http://localhost:8081/v2/materials/images", file, uId);
        System.out.println(result);
    }
}
