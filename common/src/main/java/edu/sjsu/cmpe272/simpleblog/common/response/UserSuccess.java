package edu.sjsu.cmpe272.simpleblog.common.response;

import lombok.Data;

@Data
public class UserSuccess {
    String message;

    public UserSuccess(String message) {
        this.message = message;
    }

    public UserSuccess() {

    }
}
