package com.lintsec.controller;

import com.lintsec.domain.User;
import com.lintsec.dto.UserDto;
import com.lintsec.security.AppUserPrincipal;
import com.lintsec.service.UserService;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
public class MeController {

    private final UserService userService;

    public MeController(UserService userService) {
        this.userService = userService;
    }

    @GetMapping("/me")
    public UserDto me(@AuthenticationPrincipal AppUserPrincipal principal) {
        User fresh = userService.getById(principal.id());
        return UserDto.from(fresh);
    }
}
