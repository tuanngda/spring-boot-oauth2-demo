package com.blogspot.sgdev.blog.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;

@Configuration
@EnableAuthorizationServer
public class AuthorizationServerConfiguration extends AuthorizationServerConfigurerAdapter {

	@Value("${resource.id:spring-boot-application}")
    private String resourceId;
    
    @Value("${access_token.validity_period:3600}")
    int accessTokenValiditySeconds = 3600;

    @Autowired
    private AuthenticationManager authenticationManager;
    
    @Bean
    public JwtAccessTokenConverter accessTokenConverter() {
        return new JwtAccessTokenConverter();
    }

    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        endpoints
            .authenticationManager(this.authenticationManager)
            .accessTokenConverter(accessTokenConverter());
    }
    
    @Override
    public void configure(AuthorizationServerSecurityConfigurer oauthServer) throws Exception {
        oauthServer.tokenKeyAccess("isAnonymous() || hasAuthority('ROLE_TRUSTED_CLIENT')")
            .checkTokenAccess("hasAuthority('ROLE_TRUSTED_CLIENT')");
    }

    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        clients.inMemory()
            .withClient("normal-app")
                .authorizedGrantTypes("authorization_code", "implicit")
                .authorities("ROLE_CLIENT")
                .scopes("read", "write")
                .resourceIds(resourceId)
                .accessTokenValiditySeconds(accessTokenValiditySeconds)
        .and()
            .withClient("trusted-app")
                .authorizedGrantTypes("client_credentials", "password")
                .authorities("ROLE_TRUSTED_CLIENT")
                .scopes("read", "write")
                .resourceIds(resourceId)
                .accessTokenValiditySeconds(accessTokenValiditySeconds)
                .secret("secret");
    }
}
