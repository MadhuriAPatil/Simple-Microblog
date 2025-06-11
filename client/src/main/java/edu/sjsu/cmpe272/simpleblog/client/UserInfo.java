package edu.sjsu.cmpe272.simpleblog.client;

import lombok.Data;

@Data
public class UserInfo {
    private String userId;
    private String key;

    UserInfo() {

    }
    UserInfo(String id, String privateKey) {
        userId = id;
        key = privateKey;
    }
}
