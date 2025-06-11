package edu.sjsu.cmpe272.simpleblog.server.entity;

import com.fasterxml.jackson.annotation.JsonProperty;
import edu.sjsu.cmpe272.simpleblog.common.request.UserRequest;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Lob;
import lombok.Data;

@Entity
@Data
public class User {
    @Id
    String user;

    @JsonProperty("public-key")
    @Lob
    @Column(columnDefinition = "LONGTEXT")
    String publicKey;

    public User(UserRequest usr) {
        user = usr.getUser();
        publicKey = usr.getPublicKey();
    }

    public User() {

    }
}
