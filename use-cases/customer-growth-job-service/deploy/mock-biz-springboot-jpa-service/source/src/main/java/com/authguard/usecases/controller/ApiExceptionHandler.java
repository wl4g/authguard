package com.authguard.usecases.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class ApiExceptionHandler {
  @ExceptionHandler(IllegalArgumentException.class)
  public ResponseEntity<String> notFound(IllegalArgumentException error) {
    return ResponseEntity.status(HttpStatus.NOT_FOUND).body(error.getMessage());
  }

  @ExceptionHandler(SecurityException.class)
  public ResponseEntity<String> forbidden(SecurityException error) {
    return ResponseEntity.status(HttpStatus.FORBIDDEN).body(error.getMessage());
  }

  @ExceptionHandler(IllegalStateException.class)
  public ResponseEntity<String> unauthorized(IllegalStateException error) {
    return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(error.getMessage());
  }
}
