package com.bithumbsystems.auth.model.lrc;

import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
public class EmailValidKey {
    private String time;
    private String userAccountId;
}
