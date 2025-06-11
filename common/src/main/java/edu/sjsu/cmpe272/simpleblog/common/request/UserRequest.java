package edu.sjsu.cmpe272.simpleblog.common.request;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

@Data
public class UserRequest {
    String user;

    public UserRequest(String user, String publicKey) {
        this.user = user;
        this.publicKey = publicKey;
    }

    public UserRequest() {

    }

    @JsonProperty("public-key")
    String publicKey;
}
