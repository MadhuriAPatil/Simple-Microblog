package edu.sjsu.cmpe272.simpleblog.client;

import edu.sjsu.cmpe272.simpleblog.common.request.MessageRequest;
import edu.sjsu.cmpe272.simpleblog.common.request.PaginatedRequest;
import edu.sjsu.cmpe272.simpleblog.common.request.UserRequest;
import edu.sjsu.cmpe272.simpleblog.common.response.MessageSuccess;
import edu.sjsu.cmpe272.simpleblog.common.response.MessageSuccessList;
import edu.sjsu.cmpe272.simpleblog.common.response.UserSuccess;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.*;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.client.RestTemplate;
import picocli.CommandLine;
import picocli.CommandLine.Option;
import picocli.CommandLine.Command;
import picocli.CommandLine.Parameters;
import picocli.CommandLine.IFactory;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.regex.Pattern;

@SpringBootApplication
@Command
@Slf4j
public class ClientApplication implements CommandLineRunner, ExitCodeGenerator {

    @Autowired
    CommandLine.IFactory iFactory;

    @Value("${serverUrl}")
    private String serverUrl;

    @Autowired
    private Util util;

    @Command(name = "list", description = "list messages")
    public int list(
            @CommandLine.Option(names = {"--starting"}, defaultValue = "-1", description = "Starting Id to list the messages") Long start,
            @CommandLine.Option(names = {"--count"}, defaultValue = "10", description = "Number of messages to return") Integer count,
            @CommandLine.Option(names = {"--save-attachment"}, description = "To create a file with the base64 decoded attachment named message-id.out") Boolean saveAttachment
    ) {
        try {
            final String uri = serverUrl + "/messages/list";
            List<MessageSuccess> msgList = new ArrayList<>();
            PaginatedRequest request = new PaginatedRequest();
            if (start == -1) {
                request.setNext(1000000000L);
            } else {
                request.setNext(start);
            }
            RestTemplate restTemplate = new RestTemplate();
            int page = 0;
            while (count > 0) {
                request.setLimit(20);
                request.setPage(page);
                MessageSuccessList response = restTemplate.postForObject(uri, request, MessageSuccessList.class);

                if (response != null && !response.getMsgSuccessList().isEmpty()) {
                    msgList.addAll(response.getMsgSuccessList());
                }
                count-=20;
                page++;
            }
            if (msgList.isEmpty()) {
                log.info("No messages to display");
                System.out.println("No messages to display");
                return 0;
            }
            if (saveAttachment!= null && saveAttachment) {
                util.saveAttachments(msgList);
            }

            System.out.println(util.printMessages(msgList));
            return 0;
        } catch (Exception e) {
            log.error("Error while listing the messages: {}", e.getMessage());
            return -1;
        }
    }
    @Command(name = "post", description = "Post a message")
    public int post(@Parameters String message, @Parameters(defaultValue = "null") String attachment) {
        try {
            final String uri = serverUrl + "/messages/create";
            MessageRequest request = new MessageRequest();
            UserKey userKey =  util.getUserKey();
            if (userKey == null) {
                System.out.println("User not registered, please create user and then post a message");
                return -1;
            }

            final String verifyUrl = serverUrl+"/user/"+userKey.getUserId()+"/public-key";
            RestTemplate restTemplate = new RestTemplate();

            String verificationMsg = String.valueOf(restTemplate.getForEntity(verifyUrl, String.class));

            if (verificationMsg != null && verificationMsg.contains("Username not found")) {
                String msg = "Unauthorized user, please create a new user for this client and delete any mb.ini file in current directory";
                log.error(msg);
                System.out.println(msg);
                return -1;
            }

            if (!attachment.equals("null")) {
                File file = new File(attachment);
                byte[] fileBytes = Files.readAllBytes(file.toPath());
                String encodedAttachment = Base64.getEncoder().encodeToString(fileBytes);
                request.setAttachment(encodedAttachment);
            } else {
                request.setAttachment(null);
            }

            request.setDate(LocalDateTime.now());
            request.setAuthor(userKey.getUserId());
            request.setMessage(message);

            request.setSignature(util.signMessageRequest(request, userKey));

            MessageSuccess response = restTemplate.postForObject(uri, request, MessageSuccess.class);

            if(response == null || response.getMessageId() == null) {
                log.error("Error while posting the message to the server");
                return -1;
            } else {
                log.info("Message with Id {} is saved to database", response.getMessageId());
                System.out.println("Message with Id " + response.getMessageId()+ " is saved to database");
            }
        } catch (Exception e) {
            log.error("Error while posting message {}", e.getMessage());
            return -1;
        }

        return 1;
    }

    @Command(name = "create", description = "Create a user")
    int create(@Parameters String id) {

        String regex = "^[a-z0-9]+$";
        if (!Pattern.matches(regex, id)) {
            System.out.println("User Id should only contain lower case alphabets and number");
            log.error("User Id should only contain lower case alphabets and number");
            return -1;
        }

        try {
            UserKey userKey =  util.getUserKey();

            if (userKey != null) {
                String msg = "An user is already created for this client";
                log.error(msg);
                System.out.println(msg);
                return -1;
            }

            final String verifyUrl = serverUrl+"/user/"+id+"/public-key";
            RestTemplate restTemplate = new RestTemplate();
            String verificationMsg = String.valueOf(restTemplate.getForEntity(verifyUrl, String.class));

            if (verificationMsg != null && !verificationMsg.contains("Username not found")) {
                String msg = "Duplicate userId";
                log.error(msg);
                System.out.println(msg);
                return -1;
            }

            final String uri = serverUrl + "/user/create";
            // Generate Key Pair
            KeyPair keyPair = util.generateKeyPair();

            // Save User ID and Private Key to mb.ini file
            util.saveToMbIni(id, keyPair.getPrivate());

            String publicKeyBase64 = Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());
            UserRequest request = new UserRequest(id, publicKeyBase64);
            UserSuccess response = restTemplate.postForObject(uri, request, UserSuccess.class);

            if(response == null || response.getMessage() == null) {
                log.error("Error while saving the user details in the server");
                exitCode = -1;
                return exitCode;
            }
//            else {
//                String msg ="User with Id " + id+ " and public key is saved to database";
//                System.out.println(msg);
//            }
            String res = "User with Id "+ id +" is created";
            System.out.println(res);
            return exitCode;
        } catch (Exception e) {
            log.error("Error while creating user : \n {}", e.getMessage());
            exitCode = -1;
            return exitCode;
        }
    }

    KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048); // Adjust key size as needed
        return keyPairGenerator.generateKeyPair();
    }

    void saveToMbIni(String userId, PrivateKey privateKey) {
        // Convert private key to Base64 format for storage
        String privateKeyBase64 = Base64.getEncoder().encodeToString(privateKey.getEncoded());

        // Save user ID and private key to mb.ini file
        try (FileWriter writer = new FileWriter("mb.ini")) {
            writer.write("User ID: " + userId + "\n");
            writer.write("Private Key: " + privateKeyBase64 + "\n");
        } catch (Exception e) {
            log.error("Error while saving keys to mb.ini: \n {}", e.getMessage());
        }
    }

    UserKey getUserKey() {
        String filePath = "mb.ini";

        // Variables to store userId and private key
        UserKey userKey = new UserKey();
        try {
            BufferedReader br = new BufferedReader(new FileReader(filePath));
            String line;
            while ((line = br.readLine()) != null) {
                // Split the line into key and value using ":" as delimiter
                String[] parts = line.split(":");
                if (parts.length == 2) {
                    String key = parts[0].trim();
                    String value = parts[1].trim();
                    if (key.equals("User ID")) {
                        userKey.setUserId(value);
                    } else if (key.equals("Private Key")) {
                        userKey.setKey(value);
                    }
                }
            }
            return userKey;
        } catch (Exception e) {
            log.error("Error while fetching user key from mb.ini: {}", e.getMessage());
            return null;
        }
    }

    String signMessageRequest(MessageRequest message, UserKey userKey) {
        try {
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

            PrivateKey privateKey = generatePrivateKeyFromBase64(userKey.getKey());

            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initSign(privateKey);
            signature.update(hashedMessage);
            byte[] signedBytes = signature.sign();

            String signedMessageBase64 = Base64.getEncoder().encodeToString(signedBytes);
            return signedMessageBase64;
        } catch (Exception e) {
            log.error("Error while signing message: \n {}", e.getMessage());
            return null;
        }

    }

    PrivateKey generatePrivateKeyFromBase64(String base64PrivateKey) throws NoSuchAlgorithmException, InvalidKeySpecException {
        // Decode the Base64 encoded private key to byte array
        byte[] privateKeyBytes = Base64.getDecoder().decode(base64PrivateKey);

        // Create a PKCS8EncodedKeySpec from the byte array
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyBytes);

        // Get an RSA key factory
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");

        // Generate the private key object
        PrivateKey privateKey = keyFactory.generatePrivate(keySpec);

        return privateKey;
    }

    String printMessages(List<MessageSuccess> msgList) {
        StringBuilder sb = new StringBuilder();
        for (MessageSuccess m : msgList) {
            sb.append(m.toString()+"\n");
        }
        return sb.toString();
    }

    void saveAttachments(List<MessageSuccess> msgList) {
        for (MessageSuccess m : msgList) {
            try {
                if(m.getAttachment() == null) continue;
                byte[] decodedBytes = Base64.getDecoder().decode(m.getAttachment());
                String fileName = m.getMessageId()+ ".out";
                Files.write(Paths.get(fileName), decodedBytes);
            } catch (IOException e) {
                log.error("Error while saving attachments: {}", e.getMessage());
            }
        }
    }

    public static void main(String[] args) {
        SpringApplication.run(ClientApplication.class, args);
    }

    int exitCode;

    @Override
    public void run(String... args) throws Exception {
        exitCode = new CommandLine(this, iFactory).execute(args);
    }

    @Override
    public int getExitCode() {
        return exitCode;
    }

}
