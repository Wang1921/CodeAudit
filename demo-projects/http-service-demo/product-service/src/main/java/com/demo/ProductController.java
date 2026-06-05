package com.demo;

import org.springframework.web.bind.annotation.*;

@RestController
public class ProductController {

    @GetMapping("/api/products")
    public String listProducts() {
        return "Product list";
    }
}