package com.bithumbsystems.auth.data.authentication.entity;

import lombok.Builder;
import lombok.Data;
import org.springframework.data.mongodb.core.index.Indexed;
import org.springframework.data.mongodb.core.mapping.Document;
import org.springframework.data.mongodb.core.mapping.FieldType;
import org.springframework.data.mongodb.core.mapping.MongoId;

import java.time.LocalDateTime;

@Data
@Builder
@Document("lrc_email_token")
public class LrcEmailToken {
    @MongoId(value = FieldType.STRING, targetType = FieldType.STRING)
    private String id;
    private Boolean completeYn;
    private Boolean checkOtp;
    // 토큰이 10분에 만료체크 되므로 15분 후 자동 제거
    @Indexed(name="createDateIndex", expireAfter = "900s")
    private LocalDateTime createDate;
}
