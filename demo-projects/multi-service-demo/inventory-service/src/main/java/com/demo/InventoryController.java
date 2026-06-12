package com.demo;

import org.springframework.web.bind.annotation.*;
import org.springframework.kafka.annotation.KafkaListener;
import org.xml.sax.InputSource;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.StringReader;

@RestController
public class InventoryController {

    // 监听不同的 Kafka topic - 与 order-events 无关
    @KafkaListener(topics = "inventory-updates", groupId = "inventory-group")
    public void handleInventoryUpdate(String message) {
        try {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            DocumentBuilder builder = factory.newDocumentBuilder();
            org.w3c.dom.Document doc = builder.parse(new InputSource(new StringReader(message)));
            String productId = doc.getElementsByTagName("productId").item(0).getTextContent();
            updateStock(productId);
        } catch (Exception e) {
            System.err.println("Failed to process inventory: " + e.getMessage());
        }
    }

    @GetMapping("/inventory/{productId}")
    public int getStock(@PathVariable String productId) {
        return 100;
    }

    @PostMapping("/inventory/{productId}/reserve")
    public boolean reserveStock(@PathVariable String productId, @RequestParam int quantity) {
        return true;
    }

    private void updateStock(String productId) {
        System.out.println("Updating stock for product: " + productId);
    }
}