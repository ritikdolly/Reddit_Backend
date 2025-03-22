package com.rsd.RedditBackend.dto;

import com.rsd.RedditBackend.model.VoteType;

import lombok.*;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class VoteDto {
    private VoteType voteType;
    private Long postId;
}
