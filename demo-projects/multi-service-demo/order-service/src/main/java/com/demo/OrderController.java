package com.demo;

import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.web.bind.annotation.*;

@RestController
public class OrderController {

    @KafkaListener(topics = "order-events", groupId = "order-group")
    public void handleOrderEvent(String message) {
        System.out.println("Received order event: " + message);
    }

    @PostMapping("/orders")
    public String createOrder(@RequestBody Order order) {
        KafkaTemplate<String, String> kafkaTemplate = new KafkaTemplate<>();
        kafkaTemplate.send("order-events", order.toString());
        return "Order created: " + order.getId();
    }
}

class Order {
    private String id;
    private String productName;
    private int quantity;

    public String getId() { return id; }
    public void setId(String id) { this.id = id; }
    public String getProductName() { return productName; }
    public void setProductName(String productName) { this.productName = productName; }
    public int getQuantity() { return quantity; }
    public void setQuantity(int quantity) { this.quantity = quantity; }

    @Override
    public String toString() {
        return "Order{id=" + id + ", product=" + productName + ", qty=" + quantity + "}";
    }
}