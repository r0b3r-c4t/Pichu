export interface EmailMessage {
  to: string;
  subject: string;
  html: string;
  text?: string;
}

export interface EmailSendResult {
  id: string;
}

export class EmailProviderError extends Error {
  readonly code = 'EMAIL_PROVIDER_ERROR';
  readonly providerCode?: string;

  constructor(
    message = 'Email delivery failed',
    options: { cause?: unknown; providerCode?: string } = {},
  ) {
    super(message, { cause: options.cause });
    this.providerCode = options.providerCode;
    this.name = 'EmailProviderError';
  }
}

export interface EmailProvider {
  send(message: EmailMessage): Promise<EmailSendResult>;
}
