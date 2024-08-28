package com.luxoft.spingsecurity.rest;

import com.luxoft.spingsecurity.dto.UserDto;
import com.luxoft.spingsecurity.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;

    @GetMapping("/user")
    public List<UserDto> getAll() {
        return userService.getAll();
    }

    @GetMapping("/user/{id}")
    public UserDto getById(@PathVariable("id") long userId) {
        return userService.getById(userId);
    }

    @ResponseStatus(HttpStatus.CREATED)
    @PostMapping("/user")
    @Secured("ROLE_ADMIN")
    public UserDto create(@RequestBody UserDto userDto) {
        return userService.create(userDto);
    }

    @PutMapping("/user")
    @PreAuthorize("hasRole('ADMIN')")
    public UserDto update(@RequestBody UserDto userDto) {
        return userService.update(userDto);
    }

    @GetMapping("/user/whoami")
    public UserDto whoAmI() {
        return userService.getCurrentUser();
    }
}
