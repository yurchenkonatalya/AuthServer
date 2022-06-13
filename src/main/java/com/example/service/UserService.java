package com.example.service;

import com.example.dto.JwtDto;
import com.example.model.User;

public interface UserService {
    User findByUsername(String username);
    User findById(Long id);
}
