package com.simbolmina.auth.auth;

import com.simbolmina.auth.auth.dto.*;
import com.simbolmina.auth.config.JwtService;
import com.simbolmina.auth.user.UserRepository;
import com.simbolmina.auth.user.entity.User;
import lombok.RequiredArgsConstructor;
import org.apache.coyote.BadRequestException;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.slf4j.Logger;


@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    private final UserRepository userRepository;

    private final JwtService jwtService;

    private static final Logger logger = LoggerFactory.getLogger(AuthController.class);

    @PostMapping("/register")
    public ResponseEntity<AuthenticationResponse> register(@RequestBody RegisterDTO request) {
        return ResponseEntity.ok(authService.register(request));
    }

    @PostMapping("/login")
    public ResponseEntity<AuthenticationResponse> register(@RequestBody LoginDTO request) {
        return ResponseEntity.ok(authService.login(request));

    }

    @PostMapping("/refresh")
    public ResponseEntity<AuthenticationResponse> refresh(@RequestBody RefreshTokenDTO refreshTokenDTO) {
        try {
            String providedRefreshToken = refreshTokenDTO.getRefreshToken();
            String userEmail = jwtService.extractEmail(providedRefreshToken, false);

            User user = userRepository.findByEmail(userEmail)
                    .orElseThrow(() -> new UsernameNotFoundException("User not found"));

            String storedRefreshToken = user.getRefreshToken();

            if (providedRefreshToken.equals(storedRefreshToken) && jwtService.isRefreshTokenValid(providedRefreshToken, user)) {
                String newAccessToken = jwtService.generateAccessToken(user);
                String newRefreshToken = jwtService.generateRefreshToken(user);

                user.setRefreshToken(newRefreshToken);
                userRepository.save(user);

                return ResponseEntity.ok(new AuthenticationResponse(newAccessToken, newRefreshToken));
            } else {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
            }
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).build();
        }
    }

    @PostMapping("/change-password")
    public ResponseEntity<AuthenticationResponse> changePassword(@RequestBody ChangePasswordDTO body) {
        try {
            AuthenticationResponse newTokens = authService.changePassword(body);
            return ResponseEntity.ok(newTokens);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(null);
        }
    }


}
