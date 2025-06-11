package edu.sjsu.cmpe272.simpleblog.common.response;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Data;

import java.util.List;

@Data
@JsonInclude(JsonInclude.Include.NON_NULL)
public class MessageSuccessList {
    List<MessageSuccess> msgSuccessList;
    String error;

}
