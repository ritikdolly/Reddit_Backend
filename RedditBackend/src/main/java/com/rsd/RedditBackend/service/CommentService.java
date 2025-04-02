package com.rsd.RedditBackend.service;

import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.rsd.RedditBackend.dto.CommentsDto;
import com.rsd.RedditBackend.exception.PostNotFoundException;
import com.rsd.RedditBackend.exception.SpringRedditException;
import com.rsd.RedditBackend.mapper.CommentMapper;
import com.rsd.RedditBackend.model.Comment;
import com.rsd.RedditBackend.model.NotificationEmail;
import com.rsd.RedditBackend.model.Post;
import com.rsd.RedditBackend.model.User;
import com.rsd.RedditBackend.repository.CommentRepository;
import com.rsd.RedditBackend.repository.PostRepository;
import com.rsd.RedditBackend.repository.UserRepository;

import jakarta.transaction.Transactional;

import static java.util.stream.Collectors.toList;

import java.time.Instant;
import java.util.List;

import lombok.AllArgsConstructor;

@Service
@AllArgsConstructor
public class CommentService {
    private static final String POST_URL = "";
    private final PostRepository postRepository;
    private final UserRepository userRepository;
    private final AuthService authService;
    private final CommentMapper commentMapper;
    private final CommentRepository commentRepository;
    private final MailContentBuilder mailContentBuilder;
    private final MailService mailService;

    public void save(CommentsDto commentsDto) {
        Post post = postRepository.findById(commentsDto.getPostId())
                .orElseThrow(() -> new PostNotFoundException(commentsDto.getPostId().toString()));
//        System.out.println("commentService Save");
//        System.out.println(commentsDto.getUserName());
//    	System.out.println(commentsDto.getText());
//    	System.out.println(commentsDto.getPostId());
//    	System.out.println(commentsDto.getCreatedDate());
    	System.out.println("post at commentService"+post.getPostId());
    	
    	
        Comment comment = commentMapper.map(commentsDto, post, authService.getCurrentUser());
        commentRepository.save(comment);

        String message = mailContentBuilder.build(authService.getCurrentUser() + " posted a comment on your post." + POST_URL);
        sendCommentNotification(message, post.getUser());
    }

    private void sendCommentNotification(String message, User user) {
        mailService.sendMail(new NotificationEmail(user.getUsername() + " Commented on your post", user.getEmail(), message));
    }

    @Transactional
    public List<CommentsDto> getAllCommentsForPost(Long postId) {
        Post post = postRepository.findById(postId)
                .orElseThrow(() -> new PostNotFoundException(postId.toString()));
        return commentRepository.findByPost(post)
                .stream()
                .map(commentMapper::mapToDto).collect(toList());
    }

    public List<CommentsDto> getAllCommentsForUser(String userName) {
        User user = userRepository.findByUsername(userName)
                .orElseThrow(() -> new UsernameNotFoundException(userName));
        return commentRepository.findAllByUser(user)
                .stream()
                .map(commentMapper::mapToDto)
                .collect(toList());
    }

    public boolean containsSwearWords(String comment) {
        if (comment.contains("shit")) {
            throw new SpringRedditException("Comments contains unacceptable language");
        }
        return false;
    }
}