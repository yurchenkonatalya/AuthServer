package com.example.service;

import com.example.dto.JwtDto;
import com.example.model.User;

public interface UserService {
    JwtDto auth(String token);
    User findByUsername(String username);
    User findById(Long id);
}
