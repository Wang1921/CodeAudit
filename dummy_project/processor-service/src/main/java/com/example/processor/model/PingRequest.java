package com.example.processor.model;

public class PingRequest {
    private String requestId;
    private String target;
    
    public PingRequest() {}
    
    public PingRequest(String requestId, String target) {
        this.requestId = requestId;
        this.target = target;
    }
    
    public String getRequestId() {
        return requestId;
    }
    
    public void setRequestId(String requestId) {
        this.requestId = requestId;
    }
    
    public String getTarget() {
        return target;
    }
    
    public void setTarget(String target) {
        this.target = target;
    }
}
