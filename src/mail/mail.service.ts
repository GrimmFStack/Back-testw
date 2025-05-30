import { Injectable, Logger, Inject } from '@nestjs/common';
import { MailerService } from '@nestjs-modules/mailer';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class MailService {
  private readonly logger = new Logger(MailService.name);

  constructor(
    private readonly mailerService: MailerService,
    @Inject(ConfigService)
    private readonly configService: ConfigService
  ) {}

  async sendConfirmationEmail(email: string, token: string): Promise<void> {
    const activationUrl = `${this.configService.get('BACKEND_URL')}/auth/confirm/${token}`;
    const appName = this.configService.get('APP_NAME', 'App');

    try {
      await this.mailerService.sendMail({
        from: this.configService.get('MAIL_FROM_ADDRESS'),
        to: email,
        subject: `Activa tu cuenta en ${appName}`,
        template: 'confirmation',
        context: {
          email,
          confirmUrl: activationUrl,
          appName
        }
      });
      this.logger.log(`Email de activación enviado a ${email}`);
    } catch (error) {
      this.logger.error(`Error enviando email a ${email}: ${error.message}`);
      throw new Error('Error al enviar email de confirmación');
    }
  }

  async sendPasswordResetEmail(email: string, token: string): Promise<void> {
    const resetUrl = `${this.configService.get('FRONTEND_URL')}/reset-password?token=${token}`;
    
    try {
      await this.mailerService.sendMail({
        from: this.configService.get('MAIL_FROM_ADDRESS'),
        to: email,
        subject: 'Restablece tu contraseña',
        template: 'password-reset',
        context: {
          email,
          resetUrl
        }
      });
      this.logger.log(`Email de restablecimiento enviado a ${email}`);
    } catch (error) {
      this.logger.error(`Error enviando email a ${email}: ${error.message}`);
      throw new Error('Error al enviar email de restablecimiento');
    }
  }
} 