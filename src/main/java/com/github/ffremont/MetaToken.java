package com.github.ffremont;

import java.time.LocalDateTime;
import java.util.List;

public record MetaToken(String issuer, String subject, List<String> audiences, LocalDateTime expireAt, LocalDateTime notBefore){}