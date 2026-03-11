package com.example.processor.service.impl;

import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.stereotype.Service;

@Service
public class EvalServiceImpl {

    public String evaluate(String expression) {
        ExpressionParser parser = new SpelExpressionParser();
        String result = parser.parseExpression(expression).getValue(String.class);
        return "执行结果: " + result;
    }
}
