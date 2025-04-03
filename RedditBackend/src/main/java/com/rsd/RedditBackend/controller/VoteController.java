package com.rsd.RedditBackend.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import com.rsd.RedditBackend.dto.VoteDto;
import com.rsd.RedditBackend.service.VoteService;

import lombok.AllArgsConstructor;

@RestController
@RequestMapping("/api/votes/")
@AllArgsConstructor
public class VoteController {

    private final VoteService voteService;

    @PostMapping
    public ResponseEntity<Void> vote(@RequestBody VoteDto voteDto) {
    	System.out.println("Vote ctrl "+voteDto);
        voteService.vote(voteDto);
        return new ResponseEntity<>(HttpStatus.OK);
    }
}