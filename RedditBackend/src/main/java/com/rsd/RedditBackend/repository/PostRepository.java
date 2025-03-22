package com.rsd.RedditBackend.repository;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.rsd.RedditBackend.model.Post;
import com.rsd.RedditBackend.model.Subreddit;
import com.rsd.RedditBackend.model.User;

@Repository
public interface PostRepository extends JpaRepository<Post, Long> {
    List<Post> findAllBySubreddit(Subreddit subreddit);

    List<Post> findByUser(User user);
}
