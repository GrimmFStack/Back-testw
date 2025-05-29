import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { ProductsService } from './products.service';
import { ProductsController } from './products.controller';
import { Product } from './entities/product.entity';
import { Brand } from '../brands/entities/brand.entity';
import { AuthModule } from '../auth/auth.module';
import { LogsModule } from '../action-logs/action-logs.module';
import { User } from '../users/entities/user.entity';
import { ActionLog } from '../action-logs/entities/action-log.entity';
import { ProductView } from './entities/product-view.entity';

@Module({
  imports: [
    TypeOrmModule.forFeature([
      Product,
      Brand,
      User,
      ActionLog,
      ProductView
    ]),
    
    AuthModule,    
    LogsModule, 
  ],
  controllers: [ProductsController],
  providers: [ProductsService],
  exports: [ProductsService], 
})
export class ProductsModule {}