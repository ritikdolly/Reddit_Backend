package com.rsd.RedditBackend;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableAsync;

@SpringBootApplication
@EnableAsync
public class RedditBackendApplication {

	public static void main(String[] args) {
		SpringApplication.run(RedditBackendApplication.class, args);
	}

}
