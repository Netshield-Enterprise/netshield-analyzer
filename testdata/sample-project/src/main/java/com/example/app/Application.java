package com.example.app;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Sample application that uses Log4j but does NOT use the vulnerable JNDI lookup.
 * This should be detected as UNREACHABLE by the analyzer.
 */
public class Application {
    private static final Logger logger = LogManager.getLogger(Application.class);

    public static void main(String[] args) {
        logger.info("Application started");
        
        Application app = new Application();
        app.processData("Hello, World!");
        
        logger.info("Application finished");
    }

    public void processData(String data) {
        // Simple logging - does NOT use JNDI lookup
        logger.debug("Processing data: {}", data);
        
        String result = data.toUpperCase();
        logger.info("Result: {}", result);
    }
}
