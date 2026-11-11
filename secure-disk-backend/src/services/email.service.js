import nodemailer from 'nodemailer';
import { config } from '../config/index.js';

const transporter = config.smtp
  ? nodemailer.createTransport({
      host: config.smtp.host,
      port: config.smtp.port,
      secure: config.smtp.secure,
      auth: config.smtp.auth,
      connectionTimeout: 10_000,
      greetingTimeout: 10_000,
      socketTimeout: 15_000,
    })
  : null;

export async function sendVerificationEmail(email, token) {
  if (!transporter) return false;

  await transporter.sendMail({
    from: config.smtp.from,
    to: email,
    subject: 'Подтверждение email — Secure Disk',
    text: [
      'Здравствуйте!',
      '',
      'Для подтверждения адреса электронной почты в Secure Disk используйте одноразовый код:',
      token,
      '',
      'Срок действия кода — 24 часа. Если вы не создавали аккаунт, проигнорируйте это письмо.',
    ].join('\n'),
  });
  return true;
}
