package dev.ramoverflow.payjoin.sender;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.nio.file.Files;
import java.nio.file.Path;
import javax.tools.JavaCompiler;
import javax.tools.ToolProvider;
import org.junit.jupiter.api.Test;

class ReadmeExampleTest {
    @Test
    void usageExampleCompiles() throws Exception {
        String readme = Files.readString(Path.of("README.md"));
        String startMark = "```java\n";
        int start = readme.indexOf(startMark);
        int end = readme.indexOf("```", start + startMark.length());
        String source = readme.substring(start + startMark.length(), end);
        Path dir = Files.createTempDirectory("readme-example");
        Path file = dir.resolve("SessionExample.java");
        Files.writeString(file, source);
        JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();
        assertNotNull(compiler);
        int compiled = compiler.run(null, null, null, "-classpath", System.getProperty("java.class.path"), file.toString());
        assertEquals(0, compiled);
    }
}
