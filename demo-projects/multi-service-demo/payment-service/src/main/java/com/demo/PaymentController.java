package com.demo;

import org.springframework.web.bind.annotation.*;

@RestController
public class PaymentController {

    @PostMapping("/payment/charge")
    public String charge(@RequestParam String orderId, @RequestParam double amount) {
        return "Payment processed for order: " + orderId;
    }
}