package com.example.dailydumpuserservice.controller;

import com.example.dailydumpuserservice.service.StorageService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/storage")
@CrossOrigin("http://localhost:3000")
public class StorageController {
    @Autowired
    private StorageService storageService;

    @GetMapping("/generate-presigned-url")
    public ResponseEntity<String> getPresignedUrl(@RequestParam String bucketName, @RequestParam String objectKey) {
        try {
            System.out.println("liene reached end point test");
            String url = storageService.generatePresignedUrl(bucketName, objectKey);
            return ResponseEntity.ok(url);
        } catch (Exception e) {
            return ResponseEntity.internalServerError().body("Failed to generate presigned URL: " + e.getMessage());
        }
    }
    @PostMapping("/save-user-img")
    public ResponseEntity<String> saveuserimage(@RequestParam String username, @RequestParam String url){
        try {
          storageService.saveuserphoto(username,url);
            return ResponseEntity.ok(url);
        }catch (Exception e){ return ResponseEntity.internalServerError().body("failed to upload photo");}
    }
}
