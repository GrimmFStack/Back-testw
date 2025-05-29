// src/auth/services/user-verification.service.ts
import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User } from '../../users/entities/user.entity';

@Injectable()
export class UserVerificationService {
  constructor(
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
  ) {}

  async createUnverifiedUser(userData: Partial<User>) {
    const user = this.userRepository.create(userData);
    return this.userRepository.save(user);
  }

  async findByToken(token: string) {
    return this.userRepository.findOne({
      where: { activation_token: token },
    });
  }

  async activateUser(token: string) {
    const user = await this.findByToken(token);
    if (!user) {
      throw new Error('Token inválido o usuario no encontrado');
    }

    user.is_active = true;
    user.activated_at = new Date();
    user.activation_token = null;

    return this.userRepository.save(user);
  }
}
