import { Injectable, Logger } from '@nestjs/common';
import { MailerService } from '@nestjs-modules/mailer';

@Injectable()
export class MailService {
  private readonly logger = new Logger(MailService.name);

  constructor(private readonly mailerService: MailerService) {}

  async sendConfirmationEmail(email: string, token: string, firstName?: string) {
    const activationUrl = `${process.env.FRONTEND_URL}/auth/confirm/${token}`;
    const appName = process.env.APP_NAME || 'Nuestra Plataforma';

    try {
      await this.mailerService.sendMail({
        to: email,
        subject: `Confirma tu registro en ${appName}`,
        template: 'confirmation',
        context: {
          email,
          firstName: firstName || 'Usuario',
          confirmUrl: activationUrl,
          showButton: true,
          appName,
          supportEmail: process.env.SUPPORT_EMAIL || 'soporte@example.com',
          currentYear: new Date().getFullYear()
        }
      });
      this.logger.log(`Email de confirmación enviado a ${email}`);
    } catch (error) {
      this.logger.error(`Error enviando correo a ${email}: ${error.message}`);
      throw new Error('No se pudo enviar el correo de confirmación');
    }
  }
}