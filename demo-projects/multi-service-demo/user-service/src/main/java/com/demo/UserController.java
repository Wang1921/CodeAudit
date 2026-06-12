package com.demo;

import org.springframework.web.bind.annotation.*;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.beans.factory.annotation.Value;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.xml.sax.InputSource;
import java.io.StringReader;

@RestController
public class UserController {

    // 监听同一个 Kafka topic，当收到订单事件时处理用户通知
    @KafkaListener(topics = "order-events", groupId = "user-group")
    public void handleOrderNotification(String message) {
        try {
            // 不安全的 XML 解析 - Sink
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            DocumentBuilder builder = factory.newDocumentBuilder();
            org.w3c.dom.Document doc = builder.parse(new InputSource(new StringReader(message)));
            String orderId = doc.getElementsByTagName("orderId").item(0).getTextContent();
            notifyUser(orderId);
        } catch (Exception e) {
            System.err.println("Failed to process notification: " + e.getMessage());
        }
    }

    @GetMapping("/users/{id}")
    public String getUser(@PathVariable String id) {
        return "User: " + id;
    }

    private void notifyUser(String orderId) {
        System.out.println("Notifying user about order: " + orderId);
    }
}