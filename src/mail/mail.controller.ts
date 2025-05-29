import { Controller, Get } from '@nestjs/common';
import { MailerService } from '@nestjs-modules/mailer';
import { ConfigService } from '@nestjs/config';

@Controller('mail')
export class MailController {
  constructor(
    private readonly mailerService: MailerService,
    private readonly configService: ConfigService,
    
  ) {}

  @Get('test')
  async testEmail() {
    try {
      await this.mailerService.sendMail({
        to: 'test@example.com',
        from: this.configService.get('MAIL_FROM'),
        subject: '✅ Prueba de correo desde NestJS',
        html: `
          <h1>¡Funciona!</h1>
          <p>Este correo fue enviado desde NestJS usando Mailtrap.</p>
          <p><strong>Host:</strong> ${this.configService.get('MAILTRAP_HOST')}</p>
        `,
      });
      return { 
        success: true,
        message: 'Correo de prueba enviado. Revisa tu inbox en Mailtrap.',
      };
    } catch (error) {
      return {
        success: false,
        message: 'Error al enviar el correo',
        error: error.message,
      };
    }
  }
}