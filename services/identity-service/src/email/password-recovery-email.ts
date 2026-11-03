export interface PasswordRecoveryEmailInput {
  name: string;
  resetUrl: string;
  token: string;
}

export interface PasswordRecoveryEmailContent {
  subject: string;
  html: string;
  text: string;
}

function escapeHtml(value: string): string {
  return value.replace(/[&<>'"]/g, (character) => {
    const entities: Record<string, string> = {
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      "'": '&#39;',
      '"': '&quot;',
    };
    return entities[character] ?? character;
  });
}

export function createPasswordRecoveryEmail(
  input: PasswordRecoveryEmailInput,
): PasswordRecoveryEmailContent {
  const resetLink = new URL(input.resetUrl);
  resetLink.searchParams.set('token', input.token);
  const link = resetLink.toString();
  const safeName = escapeHtml(input.name);
  const plainTextName = input.name.replace(/\s+/g, ' ').trim();
  const safeLink = escapeHtml(link);

  return {
    subject: 'Reset your PICHU password',
    html: `<p>Hello ${safeName},</p><p><a href="${safeLink}">Reset your password</a></p>`,
    text: `Hello ${plainTextName},\n\nReset your password: ${link}`,
  };
}
