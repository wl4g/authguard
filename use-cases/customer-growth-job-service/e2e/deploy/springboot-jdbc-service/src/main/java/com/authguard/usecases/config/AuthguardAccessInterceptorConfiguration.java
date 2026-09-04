package com.authguard.usecases.config;

import com.authguard.adapter.access.AuthguardAccess;
import com.authguard.adapter.filter.AuthguardAccessInterceptor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class AuthguardAccessInterceptorConfiguration implements WebMvcConfigurer {
  @Bean(destroyMethod = "close")
  public AuthguardAccessInterceptor authguardAccessInterceptor() {
    if (AuthguardAccess.isGrpcTargetConfigured()) {
      return new AuthguardAccessInterceptor(
          AuthguardAccess.HeaderAccessContextResolver.fromEnvironment(),
          AuthguardAccess.GrpcAccessContextResolver.fromEnvironment());
    }
    return new AuthguardAccessInterceptor(
        AuthguardAccess.HeaderAccessContextResolver.fromEnvironment());
  }

  @Override
  public void addInterceptors(InterceptorRegistry registry) {
    registry.addInterceptor(authguardAccessInterceptor()).addPathPatterns("/customer-growth/jobs", "/customer-growth/jobs/**");
  }
}
