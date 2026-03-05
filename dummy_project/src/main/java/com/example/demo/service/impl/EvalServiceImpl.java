package com.example.demo.service.impl;

import com.example.demo.service.EvalService;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.standard.SpelExpressionParser;

public class EvalServiceImpl implements EvalService {

    @Override
    public String evaluate(String expression) {
        ExpressionParser parser = new SpelExpressionParser();
        String result = parser.parseExpression(expression).getValue(String.class);
        return "执行结果: " + result;
    }
}
