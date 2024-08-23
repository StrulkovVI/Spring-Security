package com.luxoft.spingsecurity.security;

import com.luxoft.spingsecurity.model.User;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

@Service
public class CurrentUserService {

    public User getCurrentUser() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        // For authenticated users Principal is an UserDetails object
        UserDetailsAdapter userDetails = (UserDetailsAdapter) auth.getPrincipal();
        return userDetails.getUser();
    }
}