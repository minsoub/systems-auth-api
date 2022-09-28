package com.bithumbsystems.auth.core.model.enums;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@Getter
public enum MailForm {
  DEFAULT("[Smart Admin] 임시 비밀번호 발급", "mail/default.html"),
  CONFIRM("[Smart Admin] 임시 비밀번호 발급 - 본인 확인", "mail/confirm.html");

  private final String subject;

  private final String path;
}
