package com.example.model;

import lombok.*;

import javax.management.relation.Role;
import javax.persistence.*;
import java.util.List;

@Getter
@Setter
@Builder
@ToString
@EqualsAndHashCode
@Entity
@NoArgsConstructor
@AllArgsConstructor
@Table(name = "users")
public class User extends Base{
    @Column(name = "username")
    private String username;

    @Column(name = "password") 
    private String password;

    @ManyToMany(fetch = FetchType.EAGER)
    @JoinTable(name = "user_roles", joinColumns = {@JoinColumn(name = "user_id", referencedColumnName = "id")},
    inverseJoinColumns = {@JoinColumn(name = "role_id", referencedColumnName = "id")})
    private List<UserRole> roles;
}
