package com.example.processor.service.impl;

import org.springframework.stereotype.Service;

@Service
public class PingServiceImpl {

    public String ping(String target) {
        String cmd = "ping -c 1 " + target;
        try {
            Process process = Runtime.getRuntime().exec(cmd);
            return "正在 Ping: " + cmd;
        } catch (Exception e) {
            return "Ping 错误";
        }
    }
}
