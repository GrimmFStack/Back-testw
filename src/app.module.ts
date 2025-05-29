import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { TypeOrmModule } from '@nestjs/typeorm';

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
        synchronize: false, // Desactivado para evitar borrar datos
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
