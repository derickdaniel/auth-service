package com.microservice.authservice.config.feign;


import com.microservice.authservice.dto.NotificationRequest;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

@FeignClient("notification-service")
public interface NotificationClient {

    @PostMapping("/notification/action")
    void notifyAction(@RequestBody NotificationRequest request);

}
