package com.example.dailydumpuserservice.service;

import com.amazonaws.HttpMethod;
import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.auth.AWSStaticCredentialsProvider;
import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.regions.Regions;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3ClientBuilder;
import com.amazonaws.services.s3.model.GeneratePresignedUrlRequest;
import com.example.dailydumpuserservice.config.StorageConfig;
import com.example.dailydumpuserservice.model.User;
import com.example.dailydumpuserservice.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.awssdk.services.s3.presigner.S3Presigner;
import software.amazon.awssdk.services.s3.presigner.model.GetObjectPresignRequest;
import software.amazon.awssdk.services.s3.presigner.model.PresignedGetObjectRequest;
import software.amazon.awssdk.services.s3.presigner.model.PresignedPutObjectRequest;

import java.io.IOException;
import java.io.OutputStreamWriter;
import java.net.HttpURLConnection;
import java.net.URL;
import java.time.Duration;
import java.util.Date;

@Service
public class StorageService {
    @Value("${cloud.aws.s3.bucket.name}")
    private String bucketName;
    @Value("${cloud.aws.credentials.access-key}")
    private String accessKey;
    @Value("${cloud.aws.credentials.secret-key}")
    private String secretKey;

    @Value("${cloud.aws.region.static}")
    private String region;
    private final S3Presigner presigner;
    @Autowired
    private StorageConfig client ;
    @Autowired
    private UserRepository repository;

    public StorageService() {
        this.presigner = S3Presigner.builder()
                .region(Region.of("us-east-1"))  // Specify your region
                .build();
    }

    /* Create a pre-signed URL to download an object in a subsequent GET request. */
    public String saveuserphoto(String username,String url){
        User founduser= repository.findByUsername(username);
        founduser.setImage(url);
        repository.save(founduser);

        return "successfully added img";
    }



    public String generatePresignedUrl(String bucketName, String objectKey) throws Exception {
        try {java.util.Date expiration = new java.util.Date();
            long milliSeconds = expiration.getTime();
            milliSeconds += 1000 * 60 * 60;
            expiration.setTime(milliSeconds);
            AWSCredentials credentials = new BasicAWSCredentials(accessKey,secretKey);

            AmazonS3 s3Client = AmazonS3ClientBuilder.standard().withRegion(Regions.US_EAST_1)
                    .withCredentials(new AWSStaticCredentialsProvider(credentials)).build();

            GeneratePresignedUrlRequest generatePresignedUrlRequest =
                    new GeneratePresignedUrlRequest(bucketName, objectKey);
            generatePresignedUrlRequest.setMethod(HttpMethod.PUT);
            generatePresignedUrlRequest.setExpiration(expiration);
            URL url = s3Client.generatePresignedUrl(generatePresignedUrlRequest);

System.out.println(url+" this is test");

            return url.toString();
        } catch (Exception e) {
            // Handle specific exceptions as necessary
            throw new Exception("Error generating presigned URL", e);
        }
    }
    public static void UploadObject(URL url) throws IOException
    {
        HttpURLConnection connection=(HttpURLConnection) url.openConnection();
        connection.setDoOutput(true);
        connection.setRequestMethod("PUT");
        OutputStreamWriter out = new OutputStreamWriter(
                connection.getOutputStream());
        out.write("This text uploaded as object.");
        out.close();
        int responseCode = connection.getResponseCode();
        System.out.println("Service returned response code " + responseCode);

    }






}