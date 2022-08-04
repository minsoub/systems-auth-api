package com.bithumbsystems.auth.core.model.enums;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@Getter
public enum MailForm {
  DEFAULT("[Smart Admin] 임시 비밀번호 발급", "mail/default.html");

  private final String subject;

  private final String path;
}
