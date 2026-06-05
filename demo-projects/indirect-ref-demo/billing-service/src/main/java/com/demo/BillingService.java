package com.demo;

import org.springframework.kafka.annotation.KafkaListener;

public class BillingService {

    @KafkaListener(topics = "default-order", groupId = "billing-group")
    public void handleOrderBilling(String message) {
        System.out.println("Processing billing for order: " + message);
    }
}