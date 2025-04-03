package com.rsd.RedditBackend.config;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.Contact;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class SwaggerConfiguration {
    @Bean
    public OpenAPI customOpenAPI() {
        return new OpenAPI()
            .info(new Info()
                .title("Reddit Clone API")
                .version("1.0")
                .description("API for Reddit Clone Application")
                .contact(new Contact().name("Sahdev Puran").email("puranji461@email.com").url("http://programmingtechie.com"))
            );
    }
}
