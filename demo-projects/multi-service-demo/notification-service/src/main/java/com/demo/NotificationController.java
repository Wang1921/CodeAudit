package com.demo;

import org.springframework.web.bind.annotation.*;

@RestController
public class NotificationController {

    @PostMapping("/notify")
    public String sendNotification(@RequestParam String message) {
        return "Notification sent: " + message;
    }
}