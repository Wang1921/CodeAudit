package com.demo;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.web.bind.annotation.*;

@RestController
public class OrderController {

    @Value("${kafka.topics.orders}")
    private String orderTopic;

    @PostMapping("/orders")
    public String createOrder(@RequestBody Order order) {
        KafkaTemplate<String, String> kafkaTemplate = new KafkaTemplate<>();
        kafkaTemplate.send(orderTopic, order.toString());
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