package com.curame.zuul.oauth;


import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.cloud.context.config.annotation.RefreshScope;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

import java.util.Arrays;

@Configuration
@EnableResourceServer
@RefreshScope
public class ResourceServerConfig extends ResourceServerConfigurerAdapter {

    @Value("${config.security.oauth.jwt.key}")
    private String key;

    @Override
    public void configure(ResourceServerSecurityConfigurer resources) throws Exception {
        resources.tokenStore(tokenStore());
    }

    //verificar que tengan los permisos para acceder al zuul
    @Override
    public void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .antMatchers("/app-oauth/oauth/token")
                .permitAll()
                .antMatchers(HttpMethod.GET,"/app-users/**")
                .hasRole("ADMIN")
                .antMatchers(HttpMethod.GET,"/app-finanzas/**")
                .hasAnyRole("ADMIN","USER")
                .antMatchers(HttpMethod.GET,"/app-urgencias/**")
                .hasAnyRole("ADMIN","USER")
                .antMatchers(HttpMethod.POST,"/app-finanzas/**")
                .hasAnyRole("ADMIN","USER")
                .antMatchers(HttpMethod.POST,"/app-urgencias/**")
                .hasAnyRole("ADMIN","USER")
                .antMatchers(HttpMethod.PUT,"/app-finanzas/**")
                .hasRole("ADMIN")
                .antMatchers(HttpMethod.PUT,"/app-urgencias/**")
                .hasRole("ADMIN")
                .antMatchers(HttpMethod.DELETE,"/app-finanzas/**")
                .hasRole("ADMIN")
                .antMatchers(HttpMethod.DELETE,"/app-urgencias/**")
                .hasRole("ADMIN")
                .anyRequest().authenticated()
                .and()
                .cors().configurationSource(configurationSource());

    }


    @Bean
    public CorsConfigurationSource configurationSource() {
        CorsConfiguration cors = new CorsConfiguration();

        cors.setAllowedOrigins(Arrays.asList("*"));
        cors.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        cors.setAllowCredentials(true);
        cors.setAllowedHeaders(Arrays.asList("Authorization","Content-Type"));

        //PASAR CONFIGURACION A NUESTROS ENDPOINTS
        UrlBasedCorsConfigurationSource urlBasedCorsConfigurationSource = new UrlBasedCorsConfigurationSource();
        urlBasedCorsConfigurationSource.registerCorsConfiguration("/**",cors);

        return urlBasedCorsConfigurationSource;
    }

    //El token debe ser identico a la configuracion donde se creo, para poder
    //ser validado correctamente
    @Bean
    public JwtAccessTokenConverter accessTokenConverter(){
        JwtAccessTokenConverter jwtAccessTokenConverter = new JwtAccessTokenConverter();
        jwtAccessTokenConverter.setSigningKey(key);
        return jwtAccessTokenConverter;
    }

    @Bean
    public JwtTokenStore tokenStore(){
        return new JwtTokenStore(accessTokenConverter());
    }

    //para configurar los cors para toda la aplicacion
    //y aplique a los filtros
    @Bean
    public FilterRegistrationBean<CorsFilter> corsFilter(){
        FilterRegistrationBean<CorsFilter> bean = new FilterRegistrationBean<>(new CorsFilter(configurationSource()));
        bean.setOrder(Ordered.HIGHEST_PRECEDENCE);
        return bean;
    }


}
