package com.simbolmina.auth.auth;

import com.simbolmina.auth.auth.dto.LoginDTO;
import com.simbolmina.auth.auth.dto.AuthenticationResponse;
import com.simbolmina.auth.auth.dto.RefreshTokenDTO;
import com.simbolmina.auth.auth.dto.RegisterDTO;
import com.simbolmina.auth.config.JwtService;
import com.simbolmina.auth.user.UserRepository;
import com.simbolmina.auth.user.entity.User;
import io.jsonwebtoken.Jwt;
import lombok.RequiredArgsConstructor;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


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
        return ResponseEntity.ok(authService.authenticate(request));

    }

    @PostMapping("/refresh")
    public ResponseEntity<AuthenticationResponse> refresh(@RequestBody RefreshTokenDTO refreshTokenDTO) {
        logger.info("refreshtoken print " + refreshTokenDTO.getRefreshToken());
        try {
            // Extract email/username from the refresh token
            String userEmail = jwtService.extractEmail(refreshTokenDTO.getRefreshToken());

            logger.info("user email " + userEmail);

            // Fetch user details from the repository
            User user = userRepository.findByEmail(userEmail)
                    .orElseThrow(() -> new UsernameNotFoundException("User not found"));

            if (jwtService.isRefreshTokenValid(refreshTokenDTO.getRefreshToken(), user)) {
                String newAccessToken = jwtService.generateAccessToken(user);
                String newRefreshToken = jwtService.generateRefreshToken(user); // Optional

                // Save the new refresh token in user entity if it's regenerated
                user.setRefreshToken(newRefreshToken); // Optional
                userRepository.save(user); // Optional

                return ResponseEntity.ok(new AuthenticationResponse(newAccessToken, newRefreshToken));
            } else {
                // Handle invalid refresh token case
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
            }
        } catch (Exception e) {
            // Handle exceptions like token parsing errors
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).build();
        }
    }
}
