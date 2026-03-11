package com.example.user.controller;

import com.example.user.kafka.KafkaProducerService;
import com.example.user.kafka.KafkaReplyService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api")
public class UserController {
    
    @Autowired
    private KafkaProducerService kafkaProducer;
    
    @Autowired
    private KafkaReplyService kafkaReply;
    
    @PostMapping("/eval")
    public ResponseEntity<String> evaluate(@RequestParam String expression) {
        System.out.println("[user-service] 收到 eval 请求: " + expression);
        
        String requestId = kafkaProducer.sendEvalRequest(expression);
        
        System.out.println("[user-service] 等待回复: " + requestId);
        String result = kafkaReply.waitForReply(requestId, 10000);
        
        if (result == null) {
            return ResponseEntity.status(504).body("请求超时");
        }
        
        return ResponseEntity.ok("执行结果: " + result);
    }
    
    @PostMapping("/ping")
    public ResponseEntity<String> ping(@RequestParam String target) {
        System.out.println("[user-service] 收到 ping 请求: " + target);
        
        String requestId = kafkaProducer.sendPingRequest(target);
        
        System.out.println("[user-service] 等待回复: " + requestId);
        String result = kafkaReply.waitForReply(requestId, 10000);
        
        if (result == null) {
            return ResponseEntity.status(504).body("请求超时");
        }
        
        return ResponseEntity.ok(result);
    }
    
    @GetMapping("/health")
    public ResponseEntity<String> health() {
        return ResponseEntity.ok("user-service is healthy");
    }
}
