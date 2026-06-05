package com.demo;

import org.springframework.web.bind.annotation.*;

@RestController
public class InventoryController {

    @GetMapping("/inventory/{productId}")
    public int getStock(@PathVariable String productId) {
        return 100;
    }

    @PostMapping("/inventory/{productId}/reserve")
    public boolean reserveStock(@PathVariable String productId, @RequestParam int quantity) {
        return true;
    }
}