package com.bithumbsystems.auth.core.util.message;

import com.amazonaws.util.IOUtils;
import com.bithumbsystems.auth.api.config.AwsConfig;
import com.bithumbsystems.auth.api.config.properties.AwsProperties;
import com.bithumbsystems.auth.api.config.properties.MailProperties;
import com.bithumbsystems.auth.api.exception.MailException;
import com.bithumbsystems.auth.core.model.enums.ErrorCode;
import com.bithumbsystems.auth.core.model.enums.MailForm;
import com.bithumbsystems.auth.core.util.FileUtil;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Properties;
import javax.activation.DataHandler;
import javax.activation.DataSource;
import javax.mail.Message;
import javax.mail.MessagingException;
import javax.mail.Session;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMessage;
import javax.mail.internet.MimeMultipart;
import javax.mail.util.ByteArrayDataSource;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.ses.model.RawMessage;
import software.amazon.awssdk.services.ses.model.SendRawEmailRequest;
import software.amazon.awssdk.services.ses.model.SesException;

@Component
@RequiredArgsConstructor
@Slf4j
public class MailService implements MessageService {

  //private final CredentialsProvider credentialsProvider;
  @Value("${spring.profiles.active:}")
  private String activeProfiles;
  private final AwsProperties awsProperties;
  private final MailProperties mailProperties;
  private final AwsConfig awsConfig;

  @Override
  public void sendWithFile(MailSenderInfo mailSenderInfo) throws IOException {

    // Convert the InputStream to a byte[].
    byte[] fileContent = IOUtils.toByteArray(mailSenderInfo.getIs());

    try {
      send(fileContent, mailSenderInfo);
    } catch (MessagingException e) {
      e.getStackTrace();
    }
  }

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
  private void send(byte[] attachment, MailSenderInfo mailSenderInfo)
      throws MessagingException, IOException, javax.mail.MessagingException {
    MimeMessage message = getMimeMessage(mailSenderInfo.getEmailAddress(), mailSenderInfo.getSubject());

    // Create a multipart/alternative child container.
    MimeMultipart msgBody = new MimeMultipart("alternative");

    // Create a wrapper for the HTML and text parts.
    MimeBodyPart wrap = new MimeBodyPart();

    // Define the HTML part.
    MimeBodyPart htmlPart = new MimeBodyPart();
    htmlPart.setContent(mailSenderInfo.getBodyHTML(), "text/html; charset=UTF-8");

    // Add the text and HTML parts to the child container.
    msgBody.addBodyPart(htmlPart);

    // Add the child container to the wrapper object.
    wrap.setContent(msgBody);

    // Create a multipart/mixed parent container.
    MimeMultipart msg = new MimeMultipart("mixed");

    // Add the parent container to the message.
    message.setContent(msg);

    // Add the multipart/alternative part to the message.
    msg.addBodyPart(wrap);

    // Define the attachment.
    MimeBodyPart att = new MimeBodyPart();
    DataSource fds = new ByteArrayDataSource(attachment, "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet");
    att.setDataHandler(new DataHandler(fds));

    att.setFileName(mailSenderInfo.getFileName());

    // Add the attachment to the message.
    msg.addBodyPart(att);

    extracted(message);
    log.debug("Email sent with attachment");
  }

  @Override
  public void send(final MailSenderInfo mailSenderInfo)
      throws MessagingException, IOException, javax.mail.MessagingException {
    MimeMessage message = getMimeMessage(mailSenderInfo.getEmailAddress(), mailSenderInfo.getSubject());

    // Create a multipart/alternative child container.
    MimeMultipart msgBody = new MimeMultipart("alternative");

    // Create a wrapper for the HTML and text parts.
    MimeBodyPart wrap = new MimeBodyPart();

    // Define the HTML part.
    MimeBodyPart htmlPart = new MimeBodyPart();
    htmlPart.setContent(mailSenderInfo.getBodyHTML(), "text/html; charset=UTF-8");

    // Add the text and HTML parts to the child container.
    msgBody.addBodyPart(htmlPart);

    // Add the child container to the wrapper object.
    wrap.setContent(msgBody);

    // Create a multipart/mixed parent container.
    MimeMultipart msg = new MimeMultipart("mixed");

    // Add the parent container to the message.
    message.setContent(msg);

    // Add the multipart/alternative part to the message
    msg.addBodyPart(wrap);

    // Send the email.
    extracted(message);
    log.debug("Email sent");
  }

  private void extracted(MimeMessage message) throws IOException, MessagingException {
    // Send the email.
    try {
      log.debug("Attempting to send an email through Amazon SES " + "using the AWS SDK for Java...");

      Region region = Region.of(awsProperties.getRegion());

      ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
      message.writeTo(outputStream);

      ByteBuffer buf = ByteBuffer.wrap(outputStream.toByteArray());

      byte[] arr = new byte[buf.remaining()];
      buf.get(arr);

      SdkBytes data = SdkBytes.fromByteArray(arr);

      RawMessage rawMessage = RawMessage.builder()
          .data(data)
          .build();

      SendRawEmailRequest rawEmailRequest = SendRawEmailRequest.builder()
          .rawMessage(rawMessage)
          .build();

      awsConfig.getSesClient().sendRawEmail(rawEmailRequest);

    } catch (SesException e) {
      log.error(e.awsErrorDetails().errorMessage());
    }
  }

  private MimeMessage getMimeMessage(String emailAddress, String subject)
      throws javax.mail.MessagingException {
    MimeMessage message;
    Session session = Session.getDefaultInstance(new Properties());

    // Create a new MimeMessage object.
    message = new MimeMessage(session);

    // Add subject, from, and to lines.
    message.setSubject(subject, "UTF-8");
    message.setFrom(new InternetAddress(awsProperties.getEmailSender()));
    message.setRecipients(Message.RecipientType.TO, InternetAddress.parse(emailAddress));
    return message;
  }
}