package com.demo;

import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.stereotype.Component;
import org.xml.sax.InputSource;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.StringReader;

@Component
public class OrderEventProcessor {

    // 唯一入口：Kafka topic - 没有 HTTP 接口
    @KafkaListener(topics = "order-events", groupId = "processor-group")
    public void processOrderEvent(String message) {
        try {
            // 不安全的 XML 解析 - Sink
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            DocumentBuilder builder = factory.newDocumentBuilder();
            org.w3c.dom.Document doc = builder.parse(new InputSource(new StringReader(message)));
            String orderId = doc.getElementsByTagName("orderId").item(0).getTextContent();
            handleOrder(orderId);
        } catch (Exception e) {
            System.err.println("Failed to process order event: " + e.getMessage());
        }
    }

    private void handleOrder(String orderId) {
        System.out.println("Processing order: " + orderId);
    }
}