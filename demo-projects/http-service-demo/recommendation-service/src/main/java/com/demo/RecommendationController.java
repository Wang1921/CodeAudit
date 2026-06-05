package com.demo;

import org.springframework.web.bind.annotation.*;

@RestController
public class RecommendationController {

    @GetMapping("/api/recommendations")
    public String listRecommendations() {
        return "Recommended products";
    }
}