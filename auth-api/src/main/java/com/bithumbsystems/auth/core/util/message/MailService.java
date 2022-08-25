package com.bithumbsystems.auth.core.util.message;

import com.bithumbsystems.auth.api.config.properties.AwsProperties;
import com.bithumbsystems.auth.api.config.properties.MailProperties;
import com.bithumbsystems.auth.api.exception.MailException;
import com.bithumbsystems.auth.core.model.enums.ErrorCode;
import com.bithumbsystems.auth.core.model.enums.MailForm;
import com.bithumbsystems.auth.core.util.FileUtil;
import java.io.IOException;
import java.util.Properties;
import javax.mail.Message;
import javax.mail.MessagingException;
import javax.mail.Session;
import javax.mail.Transport;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
@Slf4j
public class MailService implements MessageService {

  private final AwsProperties awsProperties;
  private final MailProperties mailProperties;

  @Override
  public void sendMail(String emailAddress, MailForm mailForm) {
    try {
      String html = FileUtil.readResourceFile(mailForm.getPath());
      log.info("send mail: " + html);

      send(
          MailSenderInfo.builder()
              .bodyHTML(html)
              .subject(mailForm.getSubject())
              .emailAddress(emailAddress)
              .build()
      );
    } catch (MessagingException | IOException e) {
      throw new MailException(ErrorCode.FAIL_SEND_MAIL);
    }
  }
  @Override
  public void sendMail(String emailAddress, String tempPassword, MailForm mailForm) {
    try {
      String html = FileUtil.readResourceFile(mailForm.getPath());
      log.info("send mail: " + html);
      html = html.replace("[PASSWORD]", "["+tempPassword+"]");
      html = html.replace("[LOGOURL]", mailProperties.getLogoUrl());
      html = html.replace("[LOGINURL]", mailProperties.getLoginUrl());
      send(
              MailSenderInfo.builder()
                      .bodyHTML(html)
                      .subject(mailForm.getSubject())
                      .emailAddress(emailAddress)
                      .build()
      );
    } catch (MessagingException | IOException e) {
      throw new MailException(ErrorCode.FAIL_SEND_MAIL);
    }
  }


  @Override
  public void send(MailSenderInfo mailSenderInfo) throws MessagingException, IOException {
    Properties props = System.getProperties();
    props.put("mail.transport.protocol", "smtp");
    props.put("mail.smtp.port", awsProperties.getSmtpPort());
    props.put("mail.smtp.starttls.enable", "true");
    props.put("mail.smtp.auth", "true");

    // Create a Session object to represent a mail session with the specified properties.
    Session session = Session.getDefaultInstance(props);
    Transport transport = session.getTransport();
    transport.connect(awsProperties.getSesEndPoint(), awsProperties.getSmtpUserName(), awsProperties.getSmtpUserPassword());

    MimeMessage msg = new MimeMessage(session);
    msg.setFrom(new InternetAddress(awsProperties.getEmailSender(),awsProperties.getEmailSender()));
    msg.setRecipient(Message.RecipientType.TO, new InternetAddress(mailSenderInfo.getEmailAddress()));
    msg.setSubject(mailSenderInfo.getSubject(), "UTF-8");
    msg.setContent(mailSenderInfo.getBodyHTML(),"text/html; charset=UTF-8");
    transport.sendMessage(msg, msg.getAllRecipients());
  }

}