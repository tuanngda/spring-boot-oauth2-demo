/*
 * Copyright 2006-2011 the original author or authors.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package com.blogspot.sgdev.blog;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.HashMap;
import java.util.List;

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
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.web.WebAppConfiguration;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;

@RunWith(SpringJUnit4ClassRunner.class)
@SpringApplicationConfiguration(classes = Application.class)
@WebAppConfiguration
@IntegrationTest({"server.port=0", "enable.security=true"})
public class GrantByAuthorizationCodeProviderTest {
    
    @Value("${local.server.port}")
    private int port;
    
    @Test
    public void getJwtTokenByAuthorizationCode() throws JsonParseException, JsonMappingException, IOException, URISyntaxException {
        String redirectUrl = "http://localhost:"+port+"/resources/user";
        ResponseEntity<String> response = new TestRestTemplate("user","password").postForEntity("http://localhost:" + port + "/oauth/authorize?response_type=code&client_id=normal-app&redirect_uri={redirectUrl}", null, String.class,redirectUrl);
        assertEquals(HttpStatus.OK, response.getStatusCode());
        List<String> setCookie = response.getHeaders().get("Set-Cookie");
        String jSessionIdCookie = setCookie.get(0);
        String cookieValue = jSessionIdCookie.split(";")[0];
        
        HttpHeaders headers = new HttpHeaders();
        headers.add("Cookie", cookieValue);
        response = new TestRestTemplate("user","password").postForEntity("http://localhost:" + port + "oauth/authorize?response_type=code&client_id=normal-app&redirect_uri={redirectUrl}&user_oauth_approval=true&authorize=Authorize", new HttpEntity<Void>(headers), String.class, redirectUrl);
        assertEquals(HttpStatus.FOUND, response.getStatusCode());
        assertNull(response.getBody());
        String location = response.getHeaders().get("Location").get(0);
        URI locationURI = new URI(location);
        String query = locationURI.getQuery();
        
        location = "http://localhost:"+port+ "/oauth/token?"+ query + "&grant_type=authorization_code&client_id=normal-app&redirect_uri={redirectUrl}";
        
        response = new TestRestTemplate("normal-app","").postForEntity(location, new HttpEntity<Void>(new HttpHeaders()), String.class, redirectUrl);
        assertEquals(HttpStatus.OK, response.getStatusCode());
        
        HashMap jwtMap = new ObjectMapper().readValue(response.getBody(), HashMap.class);
        String accessToken = (String)jwtMap.get("access_token");
        
        headers = new HttpHeaders();
        headers.set("Authorization", "Bearer "+accessToken);
        
        response = new TestRestTemplate().exchange("http://localhost:" + port + "/resources/client", HttpMethod.GET, new HttpEntity<String>(null, headers), String.class);
        assertEquals(HttpStatus.FORBIDDEN, response.getStatusCode());
        
        response = new TestRestTemplate().exchange("http://localhost:" + port + "/resources/user", HttpMethod.GET, new HttpEntity<String>(null, headers), String.class);
        assertEquals(HttpStatus.OK, response.getStatusCode());
        
        response = new TestRestTemplate().exchange("http://localhost:" + port + "/resources/principal", HttpMethod.GET, new HttpEntity<String>(null, headers), String.class);
        assertEquals("user", response.getBody());
        
        response = new TestRestTemplate().exchange("http://localhost:" + port + "/resources/roles", HttpMethod.GET, new HttpEntity<String>(null, headers), String.class);
        assertEquals("[{\"authority\":\"ROLE_USER\"}]", response.getBody());
    }
}
