package edu.sjsu.cmpe272.simpleblog.server.controller;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import edu.sjsu.cmpe272.simpleblog.common.request.MessageRequest;
import edu.sjsu.cmpe272.simpleblog.common.request.PaginatedRequest;
import edu.sjsu.cmpe272.simpleblog.common.response.MessageSuccess;
import edu.sjsu.cmpe272.simpleblog.common.response.MessageSuccessList;
import edu.sjsu.cmpe272.simpleblog.server.entity.Message;
import edu.sjsu.cmpe272.simpleblog.server.entity.User;
import edu.sjsu.cmpe272.simpleblog.server.repository.MessageRepository;
import edu.sjsu.cmpe272.simpleblog.server.repository.UserRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Optional;


@RestController
@RequestMapping("/messages")
@Slf4j
public class MessageController {

    @Autowired
    MessageRepository repository;

    @Autowired
    UserRepository userRepository;

    @PostMapping("/create")
    public MessageSuccess createMessage(@RequestBody MessageRequest request) {
        MessageSuccess response = new MessageSuccess();
        try{
            Message msg = new Message(request);
            if(verifySignature(request)) {
                msg = repository.save(msg);
                response.setMessageId(msg.getMessageId());
            } else {
                response.setError("signature didn't match");
            }
        }catch (Exception e){
            log.error("Error while verifying message and saving: ", e);
        }
        return response;
    }

    @PostMapping("/list")
    public MessageSuccessList listMessage(@RequestBody PaginatedRequest request) {
        if (request.getLimit() > 20) {
            MessageSuccessList res = new MessageSuccessList();
            res.setError("You can fetch a maximum of 20 records at once");
            return res;
        }
        Pageable pageable = PageRequest.of(request.getPage(), request.getLimit());
        List<Message> msgList = repository.findByMessageIdLessThanEqualOrderByMessageIdDesc(request.getNext(), pageable);
        return convertToMessageSuccessList(msgList);
    }

    private MessageSuccessList convertToMessageSuccessList(List<Message> msgList) {
        List<MessageSuccess> resList = new ArrayList<>();
        for(Message msg: msgList) {
            resList.add(msg.toMessageSuccess());
        }
        MessageSuccessList res = new MessageSuccessList();
        res.setMsgSuccessList(resList);
        return res;
    }

    private boolean verifySignature(MessageRequest message) throws JsonProcessingException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, SignatureException {
        Optional<User> usr = userRepository.findById(message.getAuthor());
        if (usr.isEmpty()) {
            return false;
        }

        String base64EncodedPublicKey = usr.get().getPublicKey();
        ObjectMapper objectMapper = new ObjectMapper();
        objectMapper.registerModule(new JavaTimeModule());

        ObjectNode node = objectMapper.createObjectNode();
        node.put("date", String.valueOf(message.getDate()));
        node.put("author", message.getAuthor());
        node.put("message", message.getMessage());
        node.put("attachment", message.getAttachment());
        String jsonString = objectMapper.writeValueAsString(node);

        // Remove whitespace characters from JSON string
        String compactJsonString = jsonString.replaceAll("\\s", "");

        // Calculate SHA-256 digest
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hashedMessage = digest.digest(compactJsonString.getBytes());


        byte[] publicKeyBytes = Base64.getDecoder().decode(base64EncodedPublicKey);

        // Create a PublicKey object from the decoded bytes
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA"); // Or any other algorithm
        PublicKey key = keyFactory.generatePublic(keySpec);

        // Create a Signature object
        Signature sig = Signature.getInstance("SHA256withRSA"); // Or any other algorithm

        // Initialize the Signature object with the public key
        sig.initVerify(key);

        // Update the data to be verified
        sig.update(hashedMessage);

        // Decode the Base64-encoded signature
        byte[] signatureBytes = Base64.getDecoder().decode(message.getSignature());

        // Verify the signature
        return sig.verify(signatureBytes);
    }

}
