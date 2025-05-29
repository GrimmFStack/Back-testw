import { Injectable } from '@nestjs/common';
import { MailerService } from '@nestjs-modules/mailer';

@Injectable()
export class MailService {
  constructor(private readonly mailerService: MailerService) {}

  async sendConfirmationEmail(email: string, token: string) {
    const activationUrl = `${process.env.BACKEND_URL}/auth/confirm/${token}`;

    try {
      await this.mailerService.sendMail({
        to: email,
        subject: `Confirma tu registro en ${process.env.APP_NAME}`,
        template: process.env.NODE_ENV === 'production' ? 'verification' : 'confirmation',
        context: {
          email, // Usamos directamente el email
          appName: process.env.APP_NAME,
          currentYear: new Date().getFullYear(),
          activationUrl, // Para verification.hbs
          confirmUrl: activationUrl, // Para confirmation.hbs
          showButton: true
        },
      });
    } catch (error) {
      console.error('Error enviando correo:', error);
      throw new Error('No se pudo enviar el correo de confirmación');
    }
  }
}