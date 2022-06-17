package com.example.model;

import lombok.*;

import javax.management.relation.Role;
import javax.persistence.*;
import java.util.List;

@Data
@Entity
@Table(name = "users")
public class User{
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "objectSID")
    private String objectSID;

}
