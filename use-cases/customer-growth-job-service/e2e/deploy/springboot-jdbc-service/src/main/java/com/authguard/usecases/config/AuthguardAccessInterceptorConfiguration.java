package com.authguard.usecases.config;

import com.authguard.adapter.access.AuthguardAccess;
import com.authguard.adapter.filter.AuthguardAccessInterceptor;
import com.authguard.adapter.util.AuthguardUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class AuthguardAccessInterceptorConfiguration implements WebMvcConfigurer {
  private static final Logger AUTHGUARD_LOGGER =
      LoggerFactory.getLogger("com.authguard.adapter.e2e");

  public AuthguardAccessInterceptorConfiguration() {
    AuthguardUtils.configureLogger(
        (level, event, fields) -> {
          if (level == AuthguardUtils.LogLevel.WARN) {
            AUTHGUARD_LOGGER.warn("event={} fields={}", event, fields);
          } else {
            AUTHGUARD_LOGGER.info("event={} fields={}", event, fields);
          }
        });
  }

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
