import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { TypeOrmModule } from '@nestjs/typeorm';
import { MailerModule } from '@nestjs-modules/mailer';
import { HandlebarsAdapter } from '@nestjs-modules/mailer/dist/adapters/handlebars.adapter';
import { join } from 'path';

import { UsersModule } from './users/users.module';
import { AuthModule } from './auth/auth.module';
import { BrandsModule } from './brands/brands.module';
import { ProductsModule } from './products/products.module';
import { LogsModule } from './action-logs/action-logs.module';
import { BrandSuppliersModule } from './brand-suppliers/brand-suppliers.module';
import { MailModule } from './mail/mail.module';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      envFilePath: '.env',
    }),

    TypeOrmModule.forRootAsync({
      imports: [ConfigModule],
      useFactory: (configService: ConfigService) => ({
        type: 'postgres',
        url: configService.get<string>('DATABASE_URL'),
        autoLoadEntities: true,
        synchronize: false,
        ssl: configService.get('NODE_ENV') === 'production'
          ? { rejectUnauthorized: true }
          : false,
        extra: {
          options: "--client_encoding=UTF8"
        },
        logging: ['error', 'warn'],
      }),
      inject: [ConfigService],
    }),

    MailerModule.forRootAsync({
      imports: [ConfigModule],
      useFactory: (configService: ConfigService) => ({
        transport: {
          host: configService.get('MAILTRAP_HOST'),
          port: configService.get('MAILTRAP_PORT'),
          auth: {
            user: configService.get('MAILTRAP_USER'),
            pass: configService.get('MAILTRAP_PASSWORD'),
          },
        },
        defaults: {
          from: `"${configService.get('MAIL_FROM_NAME')}" <${configService.get('MAIL_FROM_ADDRESS')}>`,
        },
        template: {
          dir: join(__dirname, 'mail/templates'), 
          adapter: new HandlebarsAdapter(),
          options: {
            strict: true,
          },
        },
      }),
      inject: [ConfigService],
    }),

    AuthModule,
    UsersModule,
    BrandsModule,
    ProductsModule,
    BrandSuppliersModule,
    LogsModule,
    MailModule,
  ],
})
export class AppModule {}