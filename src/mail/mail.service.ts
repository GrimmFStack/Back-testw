import { Injectable } from '@nestjs/common';
import { MailerService } from '@nestjs-modules/mailer';

@Injectable()
export class MailService {
  constructor(private readonly mailerService: MailerService) {}

  // src/mail/mail.service.ts
async sendConfirmationEmail(email: string, token: string) {
  // Usa HTTPS aunque estés en desarrollo (Mailtrap lo requiere)
  const confirmUrl = `https://${process.env.BACKEND_URL}/auth/confirm/${token}`.replace('http://', '');

  await this.mailerService.sendMail({
    to: email,
    subject: 'Confirma tu registro',
    template: 'confirmation',
    context: {
      email,
      confirmUrl: confirmUrl + '?from=email', // Añade un parámetro para debug
      appName: process.env.APP_NAME,
    },
  });
}
  }
