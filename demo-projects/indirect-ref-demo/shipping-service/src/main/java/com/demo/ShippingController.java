package com.demo;

import org.springframework.web.bind.annotation.*;

@RestController
public class ShippingController {

    @PostMapping("/ship/{orderId}")
    public String shipOrder(@PathVariable String orderId) {
        return "Order shipped: " + orderId;
    }
}