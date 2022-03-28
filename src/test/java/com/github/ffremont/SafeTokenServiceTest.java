package com.github.ffremont;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.time.LocalDateTime;
import java.util.List;

class SafeTokenServiceTest {

    @Test
    public void testVerify_should_be_ok() throws Exception {
        SafeTokenService.Keys keys = SafeTokenService.generateRSAKeys();
        SafeTokenService service = new SafeTokenService(keys.privateKey(), keys.publicKey());
        MetaToken meta = new MetaToken("nw", "florent", List.of("all"), LocalDateTime.now().plusDays(1), LocalDateTime.now());

        String token = service.generate(meta);
        MetaToken result = service.verify(token, "nw");
        Assertions.assertNotNull(result);
        Assertions.assertEquals("florent", result.subject());

    }
}