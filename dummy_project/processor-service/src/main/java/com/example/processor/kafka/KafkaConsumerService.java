package com.example.processor.kafka;

import com.example.processor.model.EvalRequest;
import com.example.processor.model.EvalReply;
import com.example.processor.model.PingRequest;
import com.example.processor.model.PingReply;
import com.example.processor.service.impl.EvalServiceImpl;
import com.example.processor.service.impl.PingServiceImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.stereotype.Service;

@Service
public class KafkaConsumerService {
    
    @Autowired
    private EvalServiceImpl evalService;
    
    @Autowired
    private PingServiceImpl pingService;
    
    @Autowired
    private KafkaTemplate<String, Object> kafkaTemplate;
    
    @KafkaListener(topics = "eval-requests", groupId = "processor-service-group")
    public void handleEvalRequest(EvalRequest request) {
        System.out.println("[processor-service] 收到 eval-requests: " + request.getRequestId());
        System.out.println("[processor-service] 表达式: " + request.getExpression());
        
        try {
            String result = evalService.evaluate(request.getExpression());
            
            EvalReply reply = new EvalReply(request.getRequestId(), result);
            kafkaTemplate.send("eval-replies", request.getRequestId(), reply);
            System.out.println("[processor-service] 发送 eval-replies: " + request.getRequestId());
        } catch (Exception e) {
            System.err.println("[processor-service] 处理失败: " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    @KafkaListener(topics = "ping-requests", groupId = "processor-service-group")
    public void handlePingRequest(PingRequest request) {
        System.out.println("[processor-service] 收到 ping-requests: " + request.getRequestId());
        System.out.println("[processor-service] 目标: " + request.getTarget());
        
        try {
            String result = pingService.ping(request.getTarget());
            
            PingReply reply = new PingReply(request.getRequestId(), result);
            kafkaTemplate.send("ping-replies", request.getRequestId(), reply);
            System.out.println("[processor-service] 发送 ping-replies: " + request.getRequestId());
        } catch (Exception e) {
            System.err.println("[processor-service] 处理失败: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
