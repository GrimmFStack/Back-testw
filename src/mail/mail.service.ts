// src/mail/mail.service.ts
import { Injectable } from '@nestjs/common';
import { MailerService } from '@nestjs-modules/mailer';

@Injectable()
export class MailService {
  constructor(private readonly mailerService: MailerService) {}

  async sendConfirmationEmail(email: string, token: string) {
  const confirmUrl = `${process.env.BACKEND_URL}/auth/confirm/${token}`;

    try {
      await this.mailerService.sendMail({
        to: email,
        subject: 'Confirma tu registro en nuestra plataforma',
        template: 'confirmation', 
        context: { 
          confirmUrl,
        },
      });
    } catch (error) {
      console.error('Error al enviar correo:', error);
      throw new Error('No se pudo enviar el correo de confirmación');
    }
  }
}