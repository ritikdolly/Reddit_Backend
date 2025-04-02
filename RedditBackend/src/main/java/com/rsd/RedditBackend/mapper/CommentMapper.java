package com.rsd.RedditBackend.mapper;

import org.mapstruct.Mapper;
import org.mapstruct.Mapping;

import com.rsd.RedditBackend.dto.CommentsDto;
import com.rsd.RedditBackend.model.Comment;
import com.rsd.RedditBackend.model.Post;
import com.rsd.RedditBackend.model.User;

@Mapper(componentModel = "spring")
public interface CommentMapper {
    @Mapping(target = "id", ignore = true)
    @Mapping(target = "text", source = "commentsDto.text")
    @Mapping(target = "createdDate", expression = "java(comment.getCreatedDate() != null ? comment.getCreatedDate() : java.time.Instant.now())")
    @Mapping(target = "post", source = "post")
    @Mapping(target = "user", source = "user")
    Comment map(CommentsDto commentsDto, Post post, User user);

    @Mapping(target = "postId", expression = "java(comment.getPost().getPostId())")
    @Mapping(target = "userName", expression = "java(comment.getUser().getUsername())")
    CommentsDto mapToDto(Comment comment);
}
