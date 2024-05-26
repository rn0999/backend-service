package com.example.demo.controller;

import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class CookieController {

    @GetMapping("/api/setCookie")
    public ResponseEntity setCookie(){
        HttpHeaders httpHeaders= new HttpHeaders();
        httpHeaders.set("Set-Cookie","custom_cookie=custom;Max-Age=30");
        return ResponseEntity.ok().headers(httpHeaders).body("Success");
    }
}
