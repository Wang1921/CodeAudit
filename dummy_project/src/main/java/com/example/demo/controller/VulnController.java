package com.example.demo.controller;

import com.example.demo.service.EvalService;
import com.example.demo.service.PingService;
import com.example.demo.service.impl.EvalServiceImpl;
import com.example.demo.service.impl.PingServiceImpl;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class VulnController {

    private final EvalService evalService = new EvalServiceImpl();
    private final PingService pingService = new PingServiceImpl();

    @GetMapping("/api/eval")
    public String evaluateSpel(@RequestParam String expression) {
        return evalService.evaluate(expression);
    }
    
    @GetMapping("/api/ping")
    public String ping(@RequestParam String target) {
        return pingService.ping(target);
    }
}
