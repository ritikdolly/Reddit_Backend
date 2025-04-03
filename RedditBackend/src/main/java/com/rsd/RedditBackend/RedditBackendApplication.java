package com.rsd.RedditBackend;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.scheduling.annotation.EnableAsync;

@SpringBootApplication
@EnableAsync
@ComponentScan(basePackages = "com.rsd.RedditBackend")

public class RedditBackendApplication {

	public static void main(String[] args) {
		SpringApplication.run(RedditBackendApplication.class, args);
	}

}
