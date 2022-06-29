package com.example.dto;

import lombok.*;

@Data
@AllArgsConstructor
public class JwtDto {
    private String username;
    private String token;
}
