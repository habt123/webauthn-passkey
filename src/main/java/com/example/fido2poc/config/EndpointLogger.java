package com.example.fido2poc.config;

import java.util.Set;
import java.util.TreeSet;
import java.util.stream.Collectors;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;

@Component
public class EndpointLogger {

  private final RequestMappingHandlerMapping requestMappingHandlerMapping;

  public EndpointLogger(RequestMappingHandlerMapping requestMappingHandlerMapping) {
    this.requestMappingHandlerMapping = requestMappingHandlerMapping;
  }

  @EventListener(ApplicationReadyEvent.class)
  public void logEndpoints() {
    var dispatcherServletMappings = requestMappingHandlerMapping.getHandlerMethods();

    System.out.println("\n========================================");
    System.out.println("Application Endpoints Available:");
    System.out.println("========================================\n");

    dispatcherServletMappings.forEach((key, value) -> {
      var methods = key.getMethodsCondition().getMethods();
      var uri = extractUris(key);

      String methodsStr = methods.isEmpty() ? "ALL" : methods.stream()
          .map(Enum::toString)
          .collect(Collectors.joining(", "));

      System.out.println(String.format("%s -> %s (%s)", methodsStr, uri, value.getMethod().getName()));
    });

    System.out.println("\n========================================");
    System.out.println("Total Endpoints: " + dispatcherServletMappings.size());
    System.out.println("========================================\n");
  }

  private static Set<String> extractUris(org.springframework.web.servlet.mvc.method.RequestMappingInfo key) {
    if (key.getPathPatternsCondition() != null) {
      return new TreeSet<>(key.getPathPatternsCondition().getPatternValues());
    }
    if (key.getPatternsCondition() != null) {
      return new TreeSet<>(key.getPatternsCondition().getPatterns());
    }
    return Set.of("<no-path-pattern>");
  }
}
