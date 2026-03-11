package com.example.user.kafka;

import com.example.user.model.EvalReply;
import com.example.user.model.PingReply;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

@Service
public class KafkaReplyService {
    
    private final Map<String, CompletableFuture<String>> pendingReplies = new ConcurrentHashMap<>();
    
    @KafkaListener(topics = "eval-replies", groupId = "user-service-group")
    public void handleEvalReply(EvalReply reply) {
        System.out.println("[user-service] 收到 eval-replies: " + reply.getRequestId());
        
        CompletableFuture<String> future = pendingReplies.get(reply.getRequestId());
        if (future != null) {
            future.complete(reply.getResult());
            pendingReplies.remove(reply.getRequestId());
        }
    }
    
    @KafkaListener(topics = "ping-replies", groupId = "user-service-group")
    public void handlePingReply(PingReply reply) {
        System.out.println("[user-service] 收到 ping-replies: " + reply.getRequestId());
        
        CompletableFuture<String> future = pendingReplies.get(reply.getRequestId());
        if (future != null) {
            future.complete(reply.getOutput());
            pendingReplies.remove(reply.getRequestId());
        }
    }
    
    public String waitForReply(String requestId, long timeoutMillis) {
        CompletableFuture<String> future = new CompletableFuture<>();
        pendingReplies.put(requestId, future);
        
        try {
            return future.get(timeoutMillis, TimeUnit.MILLISECONDS);
        } catch (Exception e) {
            pendingReplies.remove(requestId);
            return null;
        }
    }
}
