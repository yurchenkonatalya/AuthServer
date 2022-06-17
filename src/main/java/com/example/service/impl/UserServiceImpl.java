package com.example.service.impl;

import com.example.dto.JwtDto;
import com.example.model.User;
import com.example.repository.UserRepository;
import com.example.service.UserService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
@Slf4j
public class UserServiceImpl implements UserService {

    private UserRepository userRepository;

    @Autowired
    public UserServiceImpl(UserRepository userRepository){
        this.userRepository = userRepository;
    }


    @Override
    public User findByObjectSID(String sid) {
        User user = userRepository.findByObjectSID(sid);
        return user;
    }
}
