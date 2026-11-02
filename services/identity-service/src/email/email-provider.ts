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

  constructor(message = 'Email delivery failed') {
    super(message);
    this.name = 'EmailProviderError';
  }
}

export interface EmailProvider {
  send(message: EmailMessage): Promise<EmailSendResult>;
}
