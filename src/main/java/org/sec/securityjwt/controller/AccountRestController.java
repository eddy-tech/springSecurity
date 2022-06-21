package org.sec.securityjwt.controller;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.sec.securityjwt.JwtUnit;
import org.sec.securityjwt.entities.AppRole;
import org.sec.securityjwt.entities.AppUser;
import org.sec.securityjwt.entities.RoleUserForm;
import org.sec.securityjwt.service.AccountService;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.security.Principal;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
public class AccountRestController {

    private AccountService accountService;

     public AccountRestController(AccountService accountService) {
        this.accountService = accountService;
    }


    @GetMapping(path = "/users")
    @PostAuthorize("hasAuthority('USER')")
    public List<AppUser> listUsers() {
        return accountService.listUsers();
    }

    @PostMapping(path = "/users")
    @PostAuthorize("hasAuthority('ADMIN')")
    public AppUser addNewUser(@RequestBody AppUser appUser) {
        return accountService.addNewUser(appUser);
    }

    @PostMapping(path = "/roles")
    @PostAuthorize("hasAuthority('ADMIN')")
    public AppRole addNewRole(@RequestBody AppRole appRole) {
        return accountService.addNewRole(appRole);
    }

    /*
    public void addRoleToUser(@RequestBody String username,@RequestBody String roleName) {
        accountService.addRoleToUser(username, roleName);
    }
     */

    @PostMapping(path = "/addRoleToUser")
    @PostAuthorize("hasAuthority('ADMIN')")
    public void addRoleToUser(@RequestBody RoleUserForm roleUserForm){
        accountService.addRoleToUser(roleUserForm.getUsername(), roleUserForm.getRoleName());
    }

    @GetMapping(path = "/username")
    @PostAuthorize("hasAuthority('ADMIN')")
    public AppUser loadUserByUsername(@RequestBody String username) {
        return accountService.loadUserByUsername(username);
    }

    @GetMapping(path = "/refreshToken")
    public void refreshToken(HttpServletRequest request, HttpServletResponse response) throws Exception {
       String authToken = request.getHeader(JwtUnit.AUTH_HEADER);
       if(authToken != null && authToken.startsWith(JwtUnit.PREFIX)){
           try {
               String jwt = authToken.substring(JwtUnit.PREFIX.length());
               Algorithm algorithm = Algorithm.HMAC256(JwtUnit.SECRET_KEY);
               JWTVerifier jwtVerifier = JWT.require(algorithm).build();
               DecodedJWT decodedJWT = jwtVerifier.verify(jwt);
               String username = decodedJWT.getSubject();
               AppUser appUser = accountService.loadUserByUsername(username);
               String jwtAccessToken = JWT.create()
                       .withSubject(appUser.getUsername())
                       .withExpiresAt(new Date(System.currentTimeMillis()+JwtUnit.EXPIRE_ACCESS_TOKEN))
                       .withIssuer(request.getRequestURL().toString())
                       .withClaim("roles",appUser.getAppRoles().stream().map(r-> r.getRoleName()).collect(Collectors.toList()))
                       .sign(algorithm);
               Map<String, String> idToken = new HashMap<>();
               idToken.put("access-token",jwtAccessToken);
               idToken.put("refresh-token",jwt);
               response.setContentType("authorisation/json");
               new ObjectMapper().writeValue(response.getOutputStream(),idToken);

           } catch (Exception e) {
               throw e;
           }
       } else {
           throw new RuntimeException("Refresh Token Required !!!!");
       }
    }
// PATH VERS LE NOM DE L'USER QUI EST AUTHENTIFIER AVEC LE Principal :-)
    @GetMapping(path = "/profile")
    public AppUser profile(Principal principal){
        return accountService.loadUserByUsername(principal.getName());
    }
}
