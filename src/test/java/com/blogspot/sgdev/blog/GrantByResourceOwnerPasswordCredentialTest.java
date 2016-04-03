package com.blogspot.sgdev.blog;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;

import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.IntegrationTest;
import org.springframework.boot.test.SpringApplicationConfiguration;
import org.springframework.boot.test.TestRestTemplate;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.jwt.Jwt;
import org.springframework.security.jwt.JwtHelper;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.web.WebAppConfiguration;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;

@RunWith(SpringJUnit4ClassRunner.class)
@SpringApplicationConfiguration(classes = Application.class)
@WebAppConfiguration
@IntegrationTest({"server.port=0", "enable.security=true"})
public class GrantByResourceOwnerPasswordCredentialTest {
    
	@Value("${local.server.port}")
	private int port;

    @SuppressWarnings({ "rawtypes", "unchecked" })
    @Test
    public void getJwtTokenByClientCredentialForUser() throws JsonParseException, JsonMappingException, IOException {
        ResponseEntity<String> response = new TestRestTemplate("trusted-app", "secret").postForEntity("http://localhost:" + port + "/oauth/token?grant_type=password&username=user&password=password", null, String.class);
        String responseText = response.getBody();
        assertEquals(HttpStatus.OK, response.getStatusCode());
        HashMap jwtMap = new ObjectMapper().readValue(responseText, HashMap.class);
        
        assertEquals("bearer", jwtMap.get("token_type"));
        assertEquals("read write", jwtMap.get("scope"));
        assertTrue(jwtMap.containsKey("access_token"));
        assertTrue(jwtMap.containsKey("expires_in"));
        assertTrue(jwtMap.containsKey("jti"));
        String accessToken = (String)jwtMap.get("access_token");
        
        Jwt jwtToken = JwtHelper.decode(accessToken);
        String claims = jwtToken.getClaims();
        HashMap claimsMap = new ObjectMapper().readValue(claims, HashMap.class);
        assertEquals("spring-boot-application", ((List<String>)claimsMap.get("aud")).get(0));
        assertEquals("trusted-app", claimsMap.get("client_id"));
        assertEquals("user", claimsMap.get("user_name"));
        assertEquals("read", ((List<String>)claimsMap.get("scope")).get(0));
        assertEquals("write", ((List<String>)claimsMap.get("scope")).get(1));
        assertEquals("ROLE_USER", ((List<String>)claimsMap.get("authorities")).get(0));
    }
    
    @SuppressWarnings({ "rawtypes", "unchecked" })
    @Test
    public void getJwtTokenByClientCredentialForAdmin() throws JsonParseException, JsonMappingException, IOException {
        ResponseEntity<String> response = new TestRestTemplate("trusted-app", "secret").postForEntity("http://localhost:" + port + "/oauth/token?grant_type=password&username=admin&password=password", null, String.class);
        String responseText = response.getBody();
        assertEquals(HttpStatus.OK, response.getStatusCode());
        HashMap jwtMap = new ObjectMapper().readValue(responseText, HashMap.class);
        
        assertEquals("bearer", jwtMap.get("token_type"));
        assertEquals("read write", jwtMap.get("scope"));
        assertTrue(jwtMap.containsKey("access_token"));
        assertTrue(jwtMap.containsKey("expires_in"));
        assertTrue(jwtMap.containsKey("jti"));
        String accessToken = (String)jwtMap.get("access_token");
        
        Jwt jwtToken = JwtHelper.decode(accessToken);
        String claims = jwtToken.getClaims();
        HashMap claimsMap = new ObjectMapper().readValue(claims, HashMap.class);
        assertEquals("spring-boot-application", ((List<String>)claimsMap.get("aud")).get(0));
        assertEquals("trusted-app", claimsMap.get("client_id"));
        assertEquals("admin", claimsMap.get("user_name"));
        assertEquals("read", ((List<String>)claimsMap.get("scope")).get(0));
        assertEquals("write", ((List<String>)claimsMap.get("scope")).get(1));
        assertEquals("ROLE_ADMIN", ((List<String>)claimsMap.get("authorities")).get(0));
    }
	
	@Test
	public void accessProtectedResourceByJwtTokenForUser() throws JsonParseException, JsonMappingException, IOException{
	    ResponseEntity<String> response = new TestRestTemplate().getForEntity("http://localhost:" + port + "/resources/user", String.class);
	    assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
	    
	    response = new TestRestTemplate("trusted-app", "secret").postForEntity("http://localhost:" + port + "/oauth/token?grant_type=password&username=user&password=password", null, String.class);
        String responseText = response.getBody();
        assertEquals(HttpStatus.OK, response.getStatusCode());
        HashMap jwtMap = new ObjectMapper().readValue(responseText, HashMap.class);
        String accessToken = (String)jwtMap.get("access_token");
        
        HttpHeaders headers = new HttpHeaders();
        headers.set("Authorization", "Bearer "+accessToken);
        
        response = new TestRestTemplate().exchange("http://localhost:" + port + "/resources/user", HttpMethod.GET, new HttpEntity<String>(null, headers), String.class);
        assertEquals(HttpStatus.OK, response.getStatusCode());
        
        response = new TestRestTemplate().exchange("http://localhost:" + port + "/resources/principal", HttpMethod.GET, new HttpEntity<String>(null, headers), String.class);
        assertEquals("user", response.getBody());
	}
	
    @Test
    public void accessProtectedResourceByJwtTokenForAdmin() throws JsonParseException, JsonMappingException, IOException{
        ResponseEntity<String> response = new TestRestTemplate().getForEntity("http://localhost:" + port + "/resources/admin", String.class);
        assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
        
        response = new TestRestTemplate("trusted-app", "secret").postForEntity("http://localhost:" + port + "/oauth/token?grant_type=password&username=admin&password=password", null, String.class);
        String responseText = response.getBody();
        assertEquals(HttpStatus.OK, response.getStatusCode());
        HashMap jwtMap = new ObjectMapper().readValue(responseText, HashMap.class);
        String accessToken = (String)jwtMap.get("access_token");
        
        HttpHeaders headers = new HttpHeaders();
        headers.set("Authorization", "Bearer "+accessToken);
        
        response = new TestRestTemplate().exchange("http://localhost:" + port + "/resources/admin", HttpMethod.GET, new HttpEntity<String>(null, headers), String.class);
        assertEquals(HttpStatus.OK, response.getStatusCode());
        
        response = new TestRestTemplate().exchange("http://localhost:" + port + "/resources/principal", HttpMethod.GET, new HttpEntity<String>(null, headers), String.class);
        assertEquals("admin", response.getBody());
    }
    
}
