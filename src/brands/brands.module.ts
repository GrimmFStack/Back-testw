import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { BrandService } from './brand.service';
import { BrandsController } from './brands.controller';
import { Brand } from './entities/brand.entity';
import { BrandView } from './entities/brands-view.entity';
import { AuthModule } from '../auth/auth.module';
import { LogsModule } from '../action-logs/action-logs.module';
import { User } from '../users/entities/user.entity';

@Module({
  imports: [
    TypeOrmModule.forFeature([Brand, User, BrandView]),
    AuthModule,
    LogsModule,
  ],
  controllers: [BrandsController],
  providers: [BrandService],
  exports: [BrandService],
})
export class BrandsModule {}