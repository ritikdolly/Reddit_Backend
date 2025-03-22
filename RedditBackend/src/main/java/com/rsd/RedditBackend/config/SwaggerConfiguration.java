package com.rsd.RedditBackend.config;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.info.Info;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class SwaggerConfiguration {

    @Bean
    public OpenAPI redditCloneApi() {
        return new OpenAPI()
                .info(new Info()
                        .title("Reddit Clone API")
                        .version("1.0")
                        .description("API for Reddit Clone Application")
                        .contact(new Contact()
                                .name("Sahdev Puran")
                                .url("http://Protech.com")
                                .email("xyz@email.com")
                        )
                        .termsOfService("http://programmingtechie.com/terms")
                );
    }
}
