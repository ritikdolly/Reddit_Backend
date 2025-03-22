package com.rsd.RedditBackend.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.rsd.RedditBackend.model.Post;
import com.rsd.RedditBackend.model.User;
import com.rsd.RedditBackend.model.Vote;

@Repository
public interface VoteRepository extends JpaRepository<Vote, Long> {
    Optional<Vote> findTopByPostAndUserOrderByVoteIdDesc(Post post, User currentUser);
}