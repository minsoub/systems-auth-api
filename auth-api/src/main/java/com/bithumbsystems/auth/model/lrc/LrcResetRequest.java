package com.bithumbsystems.auth.model.lrc;

import com.bithumbsystems.auth.data.mongodb.client.enums.Status;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class LrcResetRequest {
    String data;
}
