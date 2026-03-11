package com.example.processor.model;

public class EvalReply {
    private String requestId;
    private String result;
    
    public EvalReply() {}
    
    public EvalReply(String requestId, String result) {
        this.requestId = requestId;
        this.result = result;
    }
    
    public String getRequestId() {
        return requestId;
    }
    
    public void setRequestId(String requestId) {
        this.requestId = requestId;
    }
    
    public String getResult() {
        return result;
    }
    
    public void setResult(String result) {
        this.result = result;
    }
}
