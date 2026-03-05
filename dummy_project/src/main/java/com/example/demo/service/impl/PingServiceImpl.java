package com.example.demo.service.impl;

import com.example.demo.service.PingService;

public class PingServiceImpl implements PingService {

    @Override
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
