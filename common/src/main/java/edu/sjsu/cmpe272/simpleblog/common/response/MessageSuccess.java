package edu.sjsu.cmpe272.simpleblog.common.response;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Data;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;

@Data
@JsonInclude(JsonInclude.Include.NON_NULL)
public class MessageSuccess {
    Long messageId;
    LocalDateTime date;
    String author;

    String message;
    String attachment;

    String signature;

    String error;

    public MessageSuccess() {

    }

    public MessageSuccess(Long messageId, LocalDateTime date, String author, String message, String attachment, String signature) {
        this.messageId = messageId;
        this.date = date;
        this.author = author;
        this.message = message;
        this.attachment = attachment;
        this.signature = signature;
    }

    @Override
    public String toString() {
        String paperClip = "";
        if(attachment != null) {
            paperClip = " 📎";
        }
        ZoneId zoneId = ZoneId.systemDefault();
        ZoneOffset offset = zoneId.getRules().getOffset(LocalDateTime.now());
        String offsetString = offset.toString();
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm");

        // Format the LocalDateTime object using the formatter
        String formattedDateTime = date.format(formatter)+offsetString;
        String val = messageId + ": " + formattedDateTime + " " + author + " says " + "\"" + message+ "\"" +paperClip;
        return val;
    }
}
