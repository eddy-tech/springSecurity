package org.sec.securityjwt.security.filters;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.sec.securityjwt.JwtUnit;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;

public class JwtAuthorizationFilter extends OncePerRequestFilter {
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        if (request.getServletPath().equals("/refreshToken")){
            filterChain.doFilter(request,response);
        } else{
            String authorizationToken = request.getHeader(JwtUnit.AUTH_HEADER);
            if(authorizationToken != null && authorizationToken.startsWith(JwtUnit.PREFIX)){
                try {
                    String jwt = authorizationToken.substring(JwtUnit.PREFIX.length());
                    Algorithm algorithm = Algorithm.HMAC256(JwtUnit.SECRET_KEY);
                    JWTVerifier jwtVerifier = JWT.require(algorithm).build();
                    DecodedJWT decodedJWT = jwtVerifier.verify(jwt);
                    String username = decodedJWT.getSubject();
                    String[] roles = decodedJWT.getClaim("roles").asArray(String.class);
                    Collection<GrantedAuthority> authorities = new ArrayList<>();
                    for (String r:roles){
                        authorities.add(new SimpleGrantedAuthority(r));
                    }
                    UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(username, null, authorities);
                    SecurityContextHolder.getContext().setAuthentication(authenticationToken); // POUR AUTHENTIFIER LE USER QUI VEUT SE CONNECTER
                    filterChain.doFilter(request,response); // POUR PASSER AU SUIVANT (NEXT)

                } catch (Exception e) {
                    response.setHeader("error-message",e.getMessage());
                    response.sendError(HttpServletResponse.SC_FORBIDDEN); // ENVOYER L'ERREUR 403 DANS LE CORPS DE LA REQUETE = NON AUTHORIZATION A LA REQUETE = PAS LE DROIT D'ACCES
                }
            } else {
                filterChain.doFilter(request,response);
            }
        }

    }
}
