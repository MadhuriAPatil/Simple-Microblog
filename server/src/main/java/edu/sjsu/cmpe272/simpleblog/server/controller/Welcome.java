package edu.sjsu.cmpe272.simpleblog.server.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class Welcome {
    @GetMapping("/")
    ResponseEntity<String> getWelcome() {
        return ResponseEntity.ok("Welcome!");
    }
}
