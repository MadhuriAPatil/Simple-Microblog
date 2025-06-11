package edu.sjsu.cmpe272.simpleblog.server.controller;

import edu.sjsu.cmpe272.simpleblog.common.request.UserRequest;
import edu.sjsu.cmpe272.simpleblog.common.response.UserSuccess;
import edu.sjsu.cmpe272.simpleblog.server.entity.User;
import edu.sjsu.cmpe272.simpleblog.server.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Optional;

@RestController
@RequestMapping("/user")
public class UserController {
    @Autowired
    UserRepository repository;

    @PostMapping("/create")
    public UserSuccess createUser(@RequestBody UserRequest user) {
        User usr = new User(user);
        Optional<User> existingUser = repository.findById(user.getUser());
        if (existingUser.isPresent()) {
            return new UserSuccess("Duplicate Id");
        } else{
            repository.save(usr);
        }
        UserSuccess res = new UserSuccess("welcome");
        return res;
    }

    @GetMapping("/{userName}/public-key")
    public String getPublicKey(@PathVariable String userName) {
        try {
            Optional<User> usr = repository.findById(userName);
            if (usr.isPresent()) {
                byte[] decodedBytes = Base64.getDecoder().decode(usr.get().getPublicKey());
                X509EncodedKeySpec keySpec = new X509EncodedKeySpec(decodedBytes);
                KeyFactory keyFactory = KeyFactory.getInstance("RSA");

                PublicKey key = keyFactory.generatePublic(keySpec);
                return key.toString();
            } else {
                return "Username not found";
            }
        } catch (Exception e) {
            return "Error while fetching public key";
        }
    }
}
