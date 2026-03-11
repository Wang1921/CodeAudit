package com.example.processor.model;

public class PingReply {
    private String requestId;
    private String output;
    
    public PingReply() {}
    
    public PingReply(String requestId, String output) {
        this.requestId = requestId;
        this.output = output;
    }
    
    public String getRequestId() {
        return requestId;
    }
    
    public void setRequestId(String requestId) {
        this.requestId = requestId;
    }
    
    public String getOutput() {
        return output;
    }
    
    public void setOutput(String output) {
        this.output = output;
    }
}
