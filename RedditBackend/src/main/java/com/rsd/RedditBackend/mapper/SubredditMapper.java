package com.rsd.RedditBackend.mapper;

import org.mapstruct.InheritInverseConfiguration;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;

import com.rsd.RedditBackend.dto.SubredditDto;
import com.rsd.RedditBackend.model.Post;
import com.rsd.RedditBackend.model.Subreddit;

import java.util.List;

@Mapper(componentModel = "spring")
public interface SubredditMapper {

    @Mapping(target = "numberOfPosts", expression = "java(mapPosts(subreddit.getPosts()))")
    SubredditDto mapSubredditToDto(Subreddit subreddit);

    default Integer mapPosts(List<Post> numberOfPosts) {
    	   System.out.println("Post List: " + numberOfPosts); 
    	return (numberOfPosts != null) ? numberOfPosts.size() : 0;
    }

    @InheritInverseConfiguration
    @Mapping(target = "posts", ignore = true)
    Subreddit mapDtoToSubreddit(SubredditDto subredditDto);
    
}