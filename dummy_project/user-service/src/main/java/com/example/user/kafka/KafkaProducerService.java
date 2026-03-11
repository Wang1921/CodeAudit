package com.example.user.kafka;

import com.example.user.model.EvalRequest;
import com.example.user.model.PingRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.kafka.support.SendResult;
import org.springframework.stereotype.Service;
import org.springframework.util.concurrent.ListenableFuture;

import java.util.UUID;

@Service
public class KafkaProducerService {
    
    @Autowired
    private KafkaTemplate<String, Object> kafkaTemplate;
    
    public String sendEvalRequest(String expression) {
        String requestId = UUID.randomUUID().toString();
        EvalRequest request = new EvalRequest(requestId, expression);
        
        kafkaTemplate.send("eval-requests", requestId, request);
        System.out.println("[user-service] 发送 eval-requests: " + requestId);
        
        return requestId;
    }
    
    public String sendPingRequest(String target) {
        String requestId = UUID.randomUUID().toString();
        PingRequest request = new PingRequest(requestId, target);
        
        kafkaTemplate.send("ping-requests", requestId, request);
        System.out.println("[user-service] 发送送 ping-requests: " + requestId);
        
        return requestId;
    }
}
