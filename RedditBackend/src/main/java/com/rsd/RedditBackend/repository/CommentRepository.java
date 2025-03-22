package com.rsd.RedditBackend.repository;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.rsd.RedditBackend.model.Comment;
import com.rsd.RedditBackend.model.Post;
import com.rsd.RedditBackend.model.User;

@Repository
public interface CommentRepository extends JpaRepository<Comment, Long> {
    List<Comment> findByPost(Post post);

    List<Comment> findAllByUser(User user);
}