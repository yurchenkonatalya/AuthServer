package com.example.security;

import com.example.model.User;
import com.example.security.jwt.JwtUser;
import com.example.security.jwt.JwtUserFactory;
import com.example.service.UserService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@Slf4j
public class JwtUserDetailsService implements UserDetailsService {
    private final UserService userService;

    @Autowired
    public JwtUserDetailsService(UserService userService){
        this.userService = userService;
    }
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userService.findByObjectSID(username);
        if (user == null){
            throw new UsernameNotFoundException("User with username: " + username + " not found");
        }
        JwtUser jwtUser = JwtUserFactory.create(user);
        return jwtUser;
    }
}
