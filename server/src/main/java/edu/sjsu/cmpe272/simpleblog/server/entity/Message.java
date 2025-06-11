package edu.sjsu.cmpe272.simpleblog.server.entity;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import edu.sjsu.cmpe272.simpleblog.common.request.MessageRequest;
import edu.sjsu.cmpe272.simpleblog.common.response.MessageSuccess;
import jakarta.persistence.*;
import lombok.Data;

import java.time.LocalDateTime;

@Entity
@Data
@JsonInclude(JsonInclude.Include.NON_NULL)
public class Message {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @JsonProperty("message-id")
    Long messageId;

    LocalDateTime date;
    String author;

    String message;

    @Lob
    @Column(columnDefinition = "LONGTEXT")
    String attachment;

    @Lob
    @Column(columnDefinition = "LONGTEXT")
    String signature;

    public Message(MessageRequest msg) {
        date = msg.getDate();
        author = msg.getAuthor();
        message = msg.getMessage();
        attachment = msg.getAttachment();;
        signature = msg.getSignature();
    }

    public MessageSuccess toMessageSuccess() {
        return new MessageSuccess(messageId, date, author, message, attachment, signature);
    }

    public Message() {

    }
}
