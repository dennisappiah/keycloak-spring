package com.shopex.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/demo")
public class DemoController {

    @GetMapping
    public String hello() {
        return "Hello from Spring boot & Keycloak";
    }

    @GetMapping("/hello-2")
    public String hello2() {
        return "Hello from Spring boot & Keycloak - ADMIN";
    }
}


//@PreAuthorize("hasRole('client_user')")
//@PreAuthorize("hasRole('client_admin')")