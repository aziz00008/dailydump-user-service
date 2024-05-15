package com.example.dailydumpuserservice.controller;

import com.example.dailydumpuserservice.model.User;
import com.example.dailydumpuserservice.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/users")
@CrossOrigin("http://localhost:3000")
public class UserController {

    @Autowired
    private UserService userService;

    @GetMapping("/{userId}")
    public ResponseEntity<User> getUserById(@PathVariable String userId) {
        User user = userService.findbyUsername(userId);
        if (user != null) {
            return ResponseEntity.ok(user);
        } else {
            return ResponseEntity.notFound().build();
        }

    }
    @GetMapping("/getUser")
    public ResponseEntity<String> getimgbyUser(@RequestParam String username){
        User founduser= userService.findbyUsername(username);

        return ResponseEntity.ok(founduser.image);

    }


}