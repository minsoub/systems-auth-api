package com.bithumbsystems.auth.core.model.enums;

import lombok.AllArgsConstructor;
import lombok.Getter;

@AllArgsConstructor
@Getter
public enum TokenType {
    ACCESS("access"), REFRESH("refresh");

    private final String value;
}
