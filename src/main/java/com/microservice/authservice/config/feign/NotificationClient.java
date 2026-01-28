package com.microservice.authservice.config.feign;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

import com.microservice.authservice.dto.NotificationRequest;

import io.github.resilience4j.circuitbreaker.annotation.CircuitBreaker;

@FeignClient("notification-service")
public interface NotificationClient {
	
	Logger log = LoggerFactory.getLogger(NotificationClient.class);

	@CircuitBreaker(name = "notifyActionCB", fallbackMethod = "notifyActionFallback")
	@PostMapping("/notification/action")
	void notifyAction(@RequestBody NotificationRequest request);

	default void notifyActionFallback(Exception ex) {
		log.error("Notifcation Service - notify action failed.");
		log.error(ex.getMessage());
	}

}
