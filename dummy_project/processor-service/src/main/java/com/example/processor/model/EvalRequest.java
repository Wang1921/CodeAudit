package com.example.processor.model;

public class EvalRequest {
    private String requestId;
    private String expression;
    
    public EvalRequest() {}
    
    public EvalRequest(String requestId, String expression) {
        this.requestId = requestId;
        this.expression = expression;
    }
    
    public String getRequestId() {
        return requestId;
    }
    
    public void setRequestId(String requestId) {
        this.requestId = requestId;
    }
    
    public String getExpression() {
        return expression;
    }
    
    public void setExpression(String expression) {
        this.expression = expression;
    }
}
