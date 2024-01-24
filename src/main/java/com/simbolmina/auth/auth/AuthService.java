package com.simbolmina.auth.auth;

import com.simbolmina.auth.auth.dto.ChangePasswordDTO;
import com.simbolmina.auth.auth.dto.LoginDTO;
import com.simbolmina.auth.auth.dto.AuthenticationResponse;
import com.simbolmina.auth.auth.dto.RegisterDTO;
import com.simbolmina.auth.config.JwtService;
import com.simbolmina.auth.user.entity.Role;
import com.simbolmina.auth.user.entity.User;
import com.simbolmina.auth.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.apache.coyote.BadRequestException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;

    private final PasswordEncoder passwordEncoder;

    private final JwtService jwtService;

    private final AuthenticationManager authenticationManager;

    public AuthenticationResponse register(RegisterDTO request) {
        User user = new User(request.getEmail(), passwordEncoder.encode(request.getPassword()));
        user.setRole(Role.USER);
        var jwtToken = jwtService.generateAccessToken(user);
        var refreshToken = jwtService.generateRefreshToken(user);
        user.setRefreshToken(refreshToken);
        userRepository.save(user);

        return AuthenticationResponse.builder().accessToken(jwtToken).refreshToken(refreshToken).build();
    }

    public AuthenticationResponse login(LoginDTO request) {
        var result = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(), request.getPassword()
                )
        );
        System.out.println("result of login :" + result);
        var user = userRepository.findByEmail(request.getEmail()).orElseThrow();
        var jwtToken = jwtService.generateAccessToken(user);
        var refreshToken = jwtService.generateRefreshToken(user);
        user.setRefreshToken(refreshToken);
        userRepository.save(user);
        return AuthenticationResponse.builder().accessToken(jwtToken).refreshToken(refreshToken).build();
    }

    public AuthenticationResponse changePassword (ChangePasswordDTO body) throws BadRequestException {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        String userEmail = authentication.getName();
        User user = userRepository.findByEmail(userEmail).
                orElseThrow(()-> new UsernameNotFoundException("User not found"));

        if(!passwordEncoder.matches(body.getOldPassword(), user.getPassword())) {
            throw new BadRequestException("Invalid old password");
        }

        user.setPassword(passwordEncoder.encode(body.getNewPassword()));
        userRepository.save(user);

        var newAccessToken = jwtService.generateAccessToken(user);
        var newRefreshToken = jwtService.generateRefreshToken(user);

        user.setRefreshToken(newRefreshToken);
        userRepository.save(user);

        return AuthenticationResponse.builder()
                .accessToken(newAccessToken)
                .refreshToken(newRefreshToken)
                .build();
    }
}
