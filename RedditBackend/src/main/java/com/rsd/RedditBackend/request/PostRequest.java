package com.rsd.RedditBackend.request;

import lombok.*;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class PostRequest {
    private Long postId;
    private String subredditName;
    private String postName;
    private String url;
    private String description;
}