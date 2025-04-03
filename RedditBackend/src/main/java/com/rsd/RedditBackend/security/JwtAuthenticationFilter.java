package com.rsd.RedditBackend.security;

import java.io.IOException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private static final Logger logger = LoggerFactory.getLogger(JwtAuthenticationFilter.class);

    @Autowired
    private JwtProvider jwtProvider;

    @Autowired
    private UserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        logger.info("JwtAuthenticationFilter is running...");

        try {
            logger.info("Request in filter: {}", request.getRequestURI());

            String jwt = getJwtFromRequest(request);
            logger.info("JWT in filter: {}", jwt);

            if (StringUtils.hasText(jwt) && jwtProvider.validateToken(jwt)) {
                String username = jwtProvider.getUsernameFromJwt(jwt);
                logger.info("Extracted Username from JWT: {}", username);

                UserDetails userDetails = userDetailsService.loadUserByUsername(username);
                UsernamePasswordAuthenticationToken authentication = 
                    new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                if (SecurityContextHolder.getContext().getAuthentication() == null) {
                    SecurityContextHolder.getContext().setAuthentication(authentication);
                    logger.info("User Authenticated and Security Context Set: {}", username);
                }
            } else {
                logger.warn("No JWT token found or token invalid!");
            }
        } catch (ExpiredJwtException e) {
            logger.error("JWT Expired: {}", e.getMessage());
        } catch (UnsupportedJwtException e) {
            logger.error("Unsupported JWT: {}", e.getMessage());
        } catch (MalformedJwtException e) {
            logger.error("Malformed JWT: {}", e.getMessage());
        } catch (Exception e) {
            logger.error("Unexpected Error in JwtAuthenticationFilter: {}", e.getMessage());
        }

        filterChain.doFilter(request, response);
    }

    private String getJwtFromRequest(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");

        logger.info("Bearer Token in JWT Auth Filter: {}", bearerToken);

        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        return null;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getRequestURI();
        return path.startsWith("/api/auth/login") || path.startsWith("/api/auth/signup"); 
    }
}
