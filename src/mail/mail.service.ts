  import { Injectable } from '@nestjs/common';
  import { MailerService } from '@nestjs-modules/mailer';

  @Injectable()
  export class MailService {
    constructor(private readonly mailerService: MailerService) {}

    // src/mail/mail.service.ts
  async sendConfirmationEmail(email: string, token: string) {
  // Define la URL de activación (¡esto es lo que faltaba!)
  const activationUrl = `${process.env.BACKEND_URL}/auth/confirm/${token}`;

  try {
    await this.mailerService.sendMail({
      to: email,
      subject: 'Confirma tu registro',
      template: 'confirmation',
      context: {
        email,
        confirmUrl: activationUrl,  // Usa la variable definida
        showButton: true,
        appName: process.env.APP_NAME || 'Tienda API'
      }
    });
  } catch (error) {
    console.error('Error enviando correo:', error);
    throw new Error('No se pudo enviar el correo de confirmación');
  }
}
};
  
    
