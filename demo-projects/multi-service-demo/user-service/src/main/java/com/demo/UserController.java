package com.demo;

import org.springframework.web.bind.annotation.*;
import org.springframework.kafka.annotation.KafkaListener;

@RestController
public class UserController {

    @KafkaListener(topics = "order-events", groupId = "user-group")
    public void handleOrderNotification(String message) {
        System.out.println("User notified about order: " + message);
    }

    @GetMapping("/users/{id}")
    public String getUser(@PathVariable String id) {
        return "User: " + id;
    }
}