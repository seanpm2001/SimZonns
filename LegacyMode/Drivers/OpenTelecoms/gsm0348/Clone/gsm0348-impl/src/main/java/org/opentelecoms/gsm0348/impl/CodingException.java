package org.opentelecoms.gsm0348.impl;

import org.opentelecoms.gsm0348.api.Gsm0348Exception;

public class CodingException extends Gsm0348Exception {

  private static final long serialVersionUID = -6571638259137374832L;

  public CodingException() {
  }

  public CodingException(String message) {
    super(message);
  }

  public CodingException(Throwable cause) {
    super(cause);
  }

  public CodingException(String message, Throwable cause) {
    super(message, cause);
  }
}
