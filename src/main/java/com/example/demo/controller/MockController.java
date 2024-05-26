package com.example.demo.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

@RestController
public class MockController {

    Logger logger = LoggerFactory.getLogger(getClass());

    @GetMapping("/api/getResponse/{path}")
    public ResponseEntity getResponse(@PathVariable("path")String path, @RequestHeader(name="envId",required = false) String envId, @CookieValue(name="custom_cookie",required = false) String custom_cookie) throws InterruptedException {
        logger.info("Cookie :: {}",custom_cookie);
        logger.info("TRAFFIC :: path {}, envId {}",path,envId);
        Map<String,String> response = new HashMap<>();
        response.put("key",String.format("%s-%s-%s","graphql",path,envId));
        response.put("path",path);
        response.put("envId",envId);
        Thread.sleep(3000);
        response.put("timestamp", Instant.now().toString());
        return ResponseEntity.ok(response);
    }

}
