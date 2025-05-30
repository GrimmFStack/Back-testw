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

  async sendConfirmationEmail(email: string, token: string, firstName?: string) {
    const activationUrl = `${this.configService.get('BACKEND_URL')}/auth/confirm/${token}`;
    const appName = this.configService.get('APP_NAME', 'Nuestra Plataforma');

    try {
      await this.mailerService.sendMail({
        to: email,
        subject: `Confirma tu cuenta en ${appName}`,
        template: 'confirmation',
        context: {
          email,
          firstName: firstName || 'Usuario',
          confirmUrl: activationUrl,
          appName
        }
      });

      this.logger.log(`Email de confirmación enviado a ${email}`);
    } catch (error) {
      this.logger.error(`Error enviando correo a ${email}: ${error.message}`);
      throw new Error('No se pudo enviar el correo de confirmación');
    }
  }
}