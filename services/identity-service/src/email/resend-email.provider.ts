import { Resend, type CreateEmailOptions } from 'resend';
import { z } from 'zod';
import {
  EmailProviderError,
  type EmailMessage,
  type EmailProvider,
  type EmailSendResult,
} from './email-provider.js';

export interface ResendEmailProviderConfig {
  apiKey: string;
  fromEmail: string;
  fromName: string;
}

interface ResendResponse {
  data: { id?: unknown } | null;
  error: unknown | null;
}

export interface ResendEmailClient {
  emails: {
    send(payload: CreateEmailOptions): Promise<ResendResponse>;
  };
}

export class ResendEmailProvider implements EmailProvider {
  private readonly client: ResendEmailClient;
  private readonly from: string;

  constructor(
    config: ResendEmailProviderConfig,
    client: ResendEmailClient = new Resend(config.apiKey),
  ) {
    if (
      !z.string().email().safeParse(config.fromEmail).success ||
      /[\r\n]/.test(config.fromEmail) ||
      /[\r\n]/.test(config.fromName)
    ) {
      throw new EmailProviderError('Invalid email provider configuration');
    }

    this.client = client;
    this.from = `${config.fromName} <${config.fromEmail}>`;
  }

  async send(message: EmailMessage): Promise<EmailSendResult> {
    const payload: CreateEmailOptions = {
      from: this.from,
      to: message.to,
      subject: message.subject,
      html: message.html,
      ...(message.text === undefined ? {} : { text: message.text }),
    };

    try {
      const response = await this.client.emails.send(payload);
      if (response.error !== null) {
        throw new EmailProviderError();
      }

      const id = response.data?.id;
      if (typeof id !== 'string' || id.trim().length === 0) {
        throw new EmailProviderError();
      }

      return { id };
    } catch (error) {
      if (error instanceof EmailProviderError) {
        throw error;
      }

      throw new EmailProviderError();
    }
  }
}
