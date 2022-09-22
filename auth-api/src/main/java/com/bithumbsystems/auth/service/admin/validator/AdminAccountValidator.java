package com.bithumbsystems.auth.service.admin.validator;

import com.bithumbsystems.auth.data.mongodb.client.entity.AdminAccount;
import java.time.LocalDateTime;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class AdminAccountValidator {

  public static boolean isValidPassword(String password) {
    var regex = "^.*(?=^.{8,64}$)(?=.*\\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[~!@#$%^*]).*$";
    Pattern pattern = Pattern.compile(regex);
    Matcher matcher = pattern.matcher(password);
    return matcher.matches();
  }

  public static boolean checkPasswordUpdatePeriod(AdminAccount account) {
    final var period = 3;
    if (account.getLastPasswordUpdateDate() == null && account.getCreateDate()
        .isBefore(LocalDateTime.now().minusMonths(period))) {
      return true;
    } else if (account.getLastPasswordUpdateDate() == null) {
      return false;
    } else {
      return account.getLastPasswordUpdateDate().isBefore(LocalDateTime.now().minusMonths(period));
    }
  }
}
