package com.demo;

import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;

@RestController
public class ApiGatewayController {

    private final RestTemplate restTemplate = new RestTemplate();

    @GetMapping("/gateway/products")
    public String getProducts() {
        // 调用 product-service 的 HTTP API
        String result = restTemplate.getForObject("http://localhost:8081/api/products", String.class);
        return "Products from gateway: " + result;
    }

    @GetMapping("/gateway/recommendations")
    public String getRecommendations() {
        String result = restTemplate.getForObject("http://localhost:8082/api/recommendations", String.class);
        return "Recommendations: " + result;
    }
}