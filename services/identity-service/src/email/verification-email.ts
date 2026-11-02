export interface VerificationEmailInput {
  name: string;
  verificationUrl: string;
  token: string;
}

export interface VerificationEmailContent {
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

export function createVerificationEmail(input: VerificationEmailInput): VerificationEmailContent {
  const verificationLink = new URL(input.verificationUrl);
  verificationLink.searchParams.set('token', input.token);
  const link = verificationLink.toString();
  const safeName = escapeHtml(input.name);
  const plainTextName = input.name.replace(/\s+/g, ' ').trim();
  const safeLink = escapeHtml(link);

  return {
    subject: 'Verify your PICHU email address',
    html: `<p>Hello ${safeName},</p><p><a href="${safeLink}">Verify your email address</a></p>`,
    text: `Hello ${plainTextName},\n\nVerify your email address: ${link}`,
  };
}
