package com.github.ffremont;


import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.util.List;


class SimpleTokenTest {

    private final static String SECRET = "39bd96da-79d4-492d-9e86-6030a9343848";

    @Test
    public void testVerify_should_be_ok() throws InvalidTokenException {
        SimpleTokenService service = new SimpleTokenService(SECRET.getBytes(StandardCharsets.UTF_8));

        MetaToken meta = new MetaToken("nw", "florent", List.of("all"), LocalDateTime.now().plusDays(1), LocalDateTime.now());
        String token = service.generate(meta);

        MetaToken result = service.verify(token, "nw");
        Assertions.assertNotNull(result);
        Assertions.assertEquals("florent", result.subject());
    }

}