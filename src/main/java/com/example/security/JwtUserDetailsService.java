package com.example.security;

import com.example.model.User;
import com.example.repository.UserRepository;
import com.example.security.jwt.JwtUser;
import com.example.security.jwt.JwtUserFactory;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@Slf4j
public class JwtUserDetailsService implements UserDetailsService {
    private final UserRepository userRepository;

    @Autowired
    public JwtUserDetailsService(UserRepository userRepository){
        this.userRepository = userRepository;
    }
    @Override
    public UserDetails loadUserByUsername(String objectSID) throws UsernameNotFoundException {
        User user = userRepository.findByObjectSID(objectSID);
        if (user == null){
            throw new UsernameNotFoundException("User with objectSID: " + objectSID + " not found");
        }
        return JwtUserFactory.create(user);
    }
}
