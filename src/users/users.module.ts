import { Module, forwardRef } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { UserService } from './users.service';
import { UserController } from './users.controller';
import { User } from './entities/user.entity';
import { UsersView } from './entities/users-view.entity'; 
import { AuthModule } from '../auth/auth.module';
import { LogsModule } from '../action-logs/action-logs.module.js';



@Module({
  imports: [
    TypeOrmModule.forFeature([User, UsersView]), 
    forwardRef(() => AuthModule),
    LogsModule, 
  ],
  controllers: [UserController],
  providers: [UserService],
  exports: [UserService], 
})
export class UsersModule {}