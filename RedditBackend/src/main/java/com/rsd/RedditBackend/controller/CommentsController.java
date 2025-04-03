package com.rsd.RedditBackend.controller;

import java.util.List;
import java.util.HashMap;
import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.rsd.RedditBackend.dto.CommentsDto;
import com.rsd.RedditBackend.repository.PostRepository;
import com.rsd.RedditBackend.service.CommentService;

import lombok.AllArgsConstructor;

@RestController
@RequestMapping("/api/comments")
@AllArgsConstructor
public class CommentsController {
	private final CommentService commentService;
	private final PostRepository postRepository;

	@PostMapping
	public ResponseEntity<Map<String, String>> createComment(@RequestBody CommentsDto commentsDto) {
	    try {
	        // Debugging logs
	        System.out.println("Received Comment Payload: " + commentsDto);

	        // Check if the post exists before saving the comment
	        if (!postRepository.existsById(commentsDto.getPostId())) {
	            return ResponseEntity.status(HttpStatus.NOT_FOUND)
	                    .body(Map.of("error", "Post with ID " + commentsDto.getPostId() + " not found."));
	        }

	        // Save the comment
	        commentService.save(commentsDto);

	        // Return a JSON response instead of plain text
	        Map<String, String> response = new HashMap<>();
	        response.put("message", "Comment added successfully!");

	        return ResponseEntity.status(HttpStatus.CREATED).body(response);
	    } catch (Exception e) {
	        e.printStackTrace();

	        Map<String, String> errorResponse = new HashMap<>();
	        errorResponse.put("error", "Failed to add comment: " + e.getMessage());

	        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorResponse);
	    }
	}



	@GetMapping("/by-post/{postId}")
	public ResponseEntity<List<CommentsDto>> getAllCommentsForPost(@PathVariable Long postId) {
		System.out.println("GetAllComment Controller"+ postId);
		return ResponseEntity.status(HttpStatus.OK).body(commentService.getAllCommentsForPost(postId));
	}

	@GetMapping("/by-user/{userName}")
	public ResponseEntity<List<CommentsDto>> getAllCommentsForUser(@PathVariable String userName) {
		return ResponseEntity.status(HttpStatus.OK).body(commentService.getAllCommentsForUser(userName));
	}

}