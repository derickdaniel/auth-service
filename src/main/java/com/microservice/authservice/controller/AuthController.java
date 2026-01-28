package com.microservice.authservice.controller;

import com.microservice.authservice.config.feign.NotificationClient;
import com.microservice.authservice.dto.NotificationRequest;
import com.microservice.authservice.dto.UserInfoResponse;
import com.microservice.authservice.exception.RefreshTokenException;
import com.microservice.authservice.exception.RoleException;
import com.microservice.authservice.jwt.JwtUtils;
import com.microservice.authservice.model.*;
import com.microservice.authservice.payload.request.LoginRequest;
import com.microservice.authservice.payload.request.SignUpRequest;
import com.microservice.authservice.payload.request.TokenRefreshRequest;
import com.microservice.authservice.payload.response.JWTResponse;
import com.microservice.authservice.payload.response.MessageResponse;
import com.microservice.authservice.payload.response.TokenRefreshResponse;
import com.microservice.authservice.security.CustomUserDetails;
import com.microservice.authservice.service.RefreshTokenService;
import com.microservice.authservice.service.RoleService;
import com.microservice.authservice.service.UserService;
import lombok.RequiredArgsConstructor;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDate;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/authenticate")
@RequiredArgsConstructor
public class AuthController {

	@Autowired
	private UserService userService;
	@Autowired
	private RoleService roleService;
	@Autowired
	private RefreshTokenService refreshTokenService;
	@Autowired
	private AuthenticationManager authenticationManager;
	@Autowired
	private PasswordEncoder encoder;
	@Autowired
	private JwtUtils jwtUtils;
    @Autowired
    private NotificationClient notificationClient;

	@PostMapping("/signup")
	public ResponseEntity<?> registerUser(@RequestBody SignUpRequest signUpRequest) {

		String username = signUpRequest.getUsername();
		String email = signUpRequest.getEmail();
		String password = signUpRequest.getPassword();
		Set<String> strRoles = signUpRequest.getRoles();
		Set<Role> roles = new HashSet<>();

		if (userService.existsByUsername(username)) {
			return ResponseEntity.badRequest().body(new MessageResponse("Error: Username is already taken!"));
		}

		if (userService.existsByEmail(email)) {
			return ResponseEntity.badRequest().body(new MessageResponse("Error: Email is already taken!"));
		}

		User user = new User();
		user.setEmail(email);
		user.setUsername(username);
		user.setPassword(encoder.encode(password));

		if (strRoles != null) {
			strRoles.forEach(role -> {
				switch (role) {
				case "ROLE_ADMIN":
					Role adminRole = null;

					if (roleService.findByName(ERole.ROLE_ADMIN).isEmpty()) {
						adminRole = new Role(ERole.ROLE_ADMIN);
					} else {
						adminRole = roleService.findByName(ERole.ROLE_ADMIN)
								.orElseThrow(() -> new RoleException("Error: Admin Role is not found."));
					}

					roles.add(adminRole);

					break;
				default:
					Role userRole = null;

					if (roleService.findByName(ERole.ROLE_USER).isEmpty()) {
						userRole = new Role(ERole.ROLE_USER);
					} else {
						userRole = roleService.findByName(ERole.ROLE_USER)
								.orElseThrow(() -> new RoleException("Error: User Role is not found."));
					}

					roles.add(userRole);
				}
			});
		} else {
			roleService.findByName(ERole.ROLE_USER).ifPresentOrElse(roles::add,
					() -> roles.add(new Role(ERole.ROLE_USER)));
		}

		user.setRoles(roles);
		userService.saveUser(user);
        User userDetail = userService.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));
        notificationClient.notifyAction(
                new NotificationRequest(
                        userDetail.getEmail(),
                        UserAction.REGISTER.toString(),
                        userDetail.getUsername(), LocalDate.now()
                )
        );
		return ResponseEntity.ok(new MessageResponse("User registered successfully!"));
	}

	@PostMapping("/login")
	public ResponseEntity<?> authenticateUser(@RequestBody LoginRequest loginRequest) {
		String username = loginRequest.getUsername();
		String password = loginRequest.getPassword();

		UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(
				username, password);

		Authentication authentication = authenticationManager.authenticate(usernamePasswordAuthenticationToken);
		SecurityContextHolder.getContext().setAuthentication(authentication);
		CustomUserDetails userDetails = (CustomUserDetails) authentication.getPrincipal();
		String jwt = jwtUtils.generateJwtToken(userDetails.getUsername(), String.valueOf(userDetails.getId()));

		List<String> roles = userDetails.getAuthorities().stream().map(item -> item.getAuthority())
				.collect(Collectors.toList());

		RefreshToken refreshToken = refreshTokenService.createRefreshToken(userDetails.getId());

		JWTResponse jwtResponse = new JWTResponse();
		jwtResponse.setEmail(userDetails.getEmail());
		jwtResponse.setUsername(userDetails.getUsername());
		jwtResponse.setId(userDetails.getId());
		jwtResponse.setToken(jwt);
		jwtResponse.setRefreshToken(refreshToken.getToken());
		jwtResponse.setRoles(roles);

        User user = userService.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));

        notificationClient.notifyAction(
                new NotificationRequest(
                        user.getEmail(),
                        UserAction.LOGIN.toString(),
                        user.getUsername(), LocalDate.now()
                )
        );
		return ResponseEntity.ok(jwtResponse);
	}

	@PostMapping(value = "/refreshtoken", produces = MediaType.APPLICATION_JSON_VALUE)
	public ResponseEntity<?> refreshtoken(@RequestBody TokenRefreshRequest request) {

		String requestRefreshToken = request.getRefreshToken();

		RefreshToken token = refreshTokenService.findByToken(requestRefreshToken).orElseThrow(
				() -> new RefreshTokenException(requestRefreshToken + "Refresh token is not in database!"));

		RefreshToken deletedToken = refreshTokenService.verifyExpiration(token);

		User userRefreshToken = deletedToken.getUser();

		String newToken = jwtUtils.generateTokenFromUsername(userRefreshToken.getUsername(),
				String.valueOf(userRefreshToken.getId()));

		return ResponseEntity.ok(new TokenRefreshResponse(newToken, requestRefreshToken));
	}

    @GetMapping("/by-username/{username}")
    public UserInfoResponse getByUsername(
            @PathVariable String username) {

        User user = userService.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("User not found"));

        return new UserInfoResponse(
                user.getUsername(),
                user.getEmail()
        );
    }
}
