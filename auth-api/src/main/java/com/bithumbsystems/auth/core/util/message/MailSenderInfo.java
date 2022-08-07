package com.bithumbsystems.auth.core.util.message;

import java.io.InputStream;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@Builder
@NoArgsConstructor
public class MailSenderInfo {

  private String subject;

  private String bodyHTML;
  private String emailAddress;
  private InputStream is;
  private String fileName;

  private void setEmailAddress(String emailAddress) {
    this.emailAddress = emailAddress.trim();
  }
}