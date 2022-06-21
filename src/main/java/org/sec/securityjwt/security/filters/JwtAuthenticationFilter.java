package org.sec.securityjwt.security.filters;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.sec.securityjwt.JwtUnit;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private AuthenticationManager authenticationManager;

    public JwtAuthenticationFilter(AuthenticationManager authenticationManager) {
        super();
        this.authenticationManager = authenticationManager;
    }


    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {

        String username = request.getParameter("username");
        String password = request.getParameter("password");
        UsernamePasswordAuthenticationToken authenticateToken = new UsernamePasswordAuthenticationToken(username,password);
        return authenticationManager.authenticate(authenticateToken);
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        User user = (User) authResult.getPrincipal(); // getPrincipal() -> permet de retourner un utilisateur authentifier
        Algorithm algorithm1 = Algorithm.HMAC256(JwtUnit.SECRET_KEY);
        // CREATE ACCESS TOKEN
        String jwtAccessToken = JWT.create()
                .withSubject(user.getUsername())
                        .withExpiresAt(new Date(System.currentTimeMillis()+JwtUnit.EXPIRE_ACCESS_TOKEN))
                                .withIssuer(request.getRequestURL().toString())
                // GENERER UNE CLE PRIVE DANS LES ROLES (map -> POUR CONVERTIR UN OBJET VERS UN AUTRE) RECUPERER LA LISTE DES ROLES (Collection) ET LA CONVERTIR EN LISTE DE STRING
                                          .withClaim("roles",user.getAuthorities().stream().map(grantedAuthority ->grantedAuthority.getAuthority()).collect(Collectors.toList()))
                                                .sign(algorithm1);

        // CREATE REFRESH TOKEN
        String jwtRefreshToken = JWT.create()
                        .withSubject(user.getUsername())
                                .withExpiresAt(new Date(System.currentTimeMillis()+JwtUnit.EXPIRE_REFRESH_TOKEN))
                                        .withIssuer(request.getRequestURL().toString())
                                                .sign(algorithm1);
        Map<String, String> idToken = new HashMap<>();
        idToken.put("access-token",jwtAccessToken);
        idToken.put("refresh-token",jwtRefreshToken);
        response.setContentType("application/json");
        new ObjectMapper().writeValue(response.getOutputStream(),idToken);
    }
}

