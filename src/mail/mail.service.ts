// src/mail/mail.service.ts
import { Injectable } from '@nestjs/common';
import { MailerService } from '@nestjs-modules/mailer';

@Injectable()
export class MailService {
  constructor(private readonly mailerService: MailerService) {}

  async sendConfirmationEmail(email: string, token: string, username: string) {
    const activationUrl = `${process.env.BACKEND_URL}/auth/confirm/${token}`;

    try {
      await this.mailerService.sendMail({
        to: email,
        subject: 'Confirma tu registro en ' + process.env.APP_NAME,
        template: process.env.NODE_ENV === 'production' ? 'verification' : 'confirmation',
        context: {
          username,
          appName: process.env.APP_NAME || 'Tu App',
          currentYear: new Date().getFullYear(),
          // Para verification.hbs
          activationUrl, 
          // Para confirmation.hbs
          confirmUrl: activationUrl, // Ahora apunta directamente al backend
          // Eliminamos el redirect al frontend
          showButton: true // Añadimos flag para mostrar botón solo en email
        },
      });
    } catch (error) {
      console.error('Error enviando correo:', error);
      throw new Error('No se pudo enviar el correo de confirmación');
    }
  }
}