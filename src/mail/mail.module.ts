import { Module } from '@nestjs/common';
import { MailerModule } from '@nestjs-modules/mailer';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { MailService } from './mail.service';
import { HandlebarsAdapter } from '@nestjs-modules/mailer/dist/adapters/handlebars.adapter';
import { join } from 'path';

@Module({
  imports: [
    MailerModule.forRootAsync({
      imports: [ConfigModule],
      useFactory: async (config: ConfigService) => ({
        transport: {
          host: config.get('MAIL_HOST', 'sandbox.smtp.mailtrap.io'),
          port: config.get('MAIL_PORT', 2525),
          secure: config.get('MAIL_SECURE', false),
          auth: {
            user: config.get('MAIL_USER'),
            pass: config.get('MAIL_PASSWORD'),
          },
          pool: true,
          maxConnections: 5,
          rateLimit: 5
        },
        defaults: {
          from: `"${config.get('MAIL_FROM_NAME', 'No Reply')}" <${config.get('MAIL_FROM_ADDRESS', 'no-reply@example.com')}>`,
        },
        template: {
          dir: join(__dirname, 'templates'),
          adapter: new HandlebarsAdapter(),
          options: {
            strict: true,
          },
        },
        logger: config.get('NODE_ENV') === 'development',
        debug: config.get('NODE_ENV') === 'development',
      }),
      inject: [ConfigService],
    }),
  ],
  providers: [MailService],
  exports: [MailService],
})
export class MailModule {}