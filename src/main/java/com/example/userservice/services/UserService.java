package com.example.userservice.services;

import com.example.userservice.models.Role;
import com.example.userservice.models.User;

import java.util.List;

public interface UserService {
    User saveUser(User user);
    Role saveRole(Role role);
    void addRoleToUser(String username, String rolename);
    User getUser(String username);
    List<User> getUsers();
}
