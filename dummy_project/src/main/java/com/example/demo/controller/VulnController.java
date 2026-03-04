package com.example.demo.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.standard.SpelExpressionParser;

@RestController
public class VulnController {

    // 典型的 SpEL (Spring Expression Language) 代码注入漏洞
    @GetMapping("/api/eval")
    public String evaluateSpel(@RequestParam String expression) {
        // [WARNING] 危险：直接接收用户输入作为表达式执行
        ExpressionParser parser = new SpelExpressionParser();
        // 攻击 Payload 示例: T(java.lang.Runtime).getRuntime().exec("calc")
        String result = parser.parseExpression(expression).getValue(String.class);
        return "执行结果: " + result;
    }
    
    // 命令注入漏洞 (OS Command Injection)
    @GetMapping("/api/ping")
    public String ping(@RequestParam String target) {
        // [WARNING] 危险：未经转义直接将输入拼接到系统命令中
        String cmd = "ping -c 1 " + target;
        try {
            // 攻击 Payload 示例: 127.0.0.1; whoami
            Process process = Runtime.getRuntime().exec(cmd);
            return "正在 Ping: " + cmd;
        } catch (Exception e) {
            return "Ping 错误";
        }
    }
}
