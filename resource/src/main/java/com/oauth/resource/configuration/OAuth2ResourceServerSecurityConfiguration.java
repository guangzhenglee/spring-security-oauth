package com.oauth.resource.configuration;

import com.nimbusds.jose.proc.JWSAlgorithmFamilyJWSKeySelector;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import com.nimbusds.jwt.proc.JWTClaimsSetVerifier;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.resource.web.BearerTokenResolver;
import org.springframework.security.oauth2.server.resource.web.DefaultBearerTokenResolver;
import org.springframework.security.web.SecurityFilterChain;

import java.net.URL;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

@EnableWebSecurity
public class OAuth2ResourceServerSecurityConfiguration {

    //	@Value("${spring.security.oauth2.resourceserver.jwt.jwk-set-uri}")
    private String jwkUri = "https://openam.example.com/openam/oauth2/realms/root/realms/sg-external/connect/jwk_uri";


    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        http.authorizeHttpRequests((authorize) -> authorize.anyRequest().authenticated()).oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt);

        return http.build();
    }

    @Bean
        BearerTokenResolver bearerTokenResolver() {
        DefaultBearerTokenResolver tokenResolver = new DefaultBearerTokenResolver();
        tokenResolver.setBearerTokenHeaderName("authority");
        return tokenResolver;
    }

    @Bean
    JwtDecoder jwtDecoder() throws Exception {
        // makes a request to the JWK Set endpoint
        JWSKeySelector<SecurityContext> jwsKeySelector = JWSAlgorithmFamilyJWSKeySelector.fromJWKSetURL(new URL(jwkUri));
        DefaultJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();
        jwtProcessor.setJWSKeySelector(jwsKeySelector);

        jwtProcessor.setJWTClaimsSetVerifier(customJwtClaimVerifier());

        NimbusJwtDecoder jwtDecoder = new NimbusJwtDecoder(jwtProcessor);

        // remove the default time validator, since we already do it in claim verifier
        OAuth2TokenValidator<Jwt> emptyValidator = new DelegatingOAuth2TokenValidator<>();
        jwtDecoder.setJwtValidator(emptyValidator);

        return jwtDecoder;
    }


    private JWTClaimsSetVerifier customJwtClaimVerifier() {
        final int MAX_CLOCK_SKEW_SECONDS = 5;
        final JWTClaimsSet exactMatchClaims = new JWTClaimsSet.Builder()
                .claim("token_type", "authority")
                .build();
        final Set<String> requiredClaims = new HashSet<>(Arrays.asList("exp"));

        DefaultJWTClaimsVerifier<?> verifier = new DefaultJWTClaimsVerifier<>(exactMatchClaims, requiredClaims);
        verifier.setMaxClockSkew(MAX_CLOCK_SKEW_SECONDS);
        return verifier;
    }
}
