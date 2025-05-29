import {
  Injectable,
  NotFoundException,
  BadRequestException,
  Inject,
  forwardRef,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import * as bcrypt from 'bcrypt';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { ReplaceUserDto } from './dto/replace-user.dto';
import { User } from './entities/user.entity';
import { UsersView } from './entities/users-view.entity';
import { ActionLogsService } from '../action-logs/action-logs.service';
import { AuthService } from '../auth/auth.service';

@Injectable()
export class UserService {
  constructor(
    @InjectRepository(User)
    private userRepository: Repository<User>,
    @InjectRepository(UsersView)
    private usersViewRepository: Repository<UsersView>,
    private actionLogsService: ActionLogsService,
    @Inject(forwardRef(() => AuthService))
    private authService: AuthService,
  ) {}

  // Métodos CRUD básicos
  async create(createUserDto: CreateUserDto): Promise<User> {
    const user = this.userRepository.create(createUserDto);
    return await this.userRepository.save(user);
  }

  async findAll(): Promise<User[]> {
    return this.userRepository.find();
  }

  async findOne(id: number): Promise<Partial<UsersView>> {
    const user = await this.usersViewRepository.findOne({ where: { user_id: id } });
    if (!user) {
      throw new NotFoundException('User not found');
    }
    return {
      user_id: user.user_id,
      email: user.email,
      is_active: user.is_active,
    };
  }

  async findOneActive(user_id: number): Promise<User | null> {
    return this.userRepository.findOne({
      where: { user_id, is_active: true },
    });
  }

  async update(
    id: number,
    updateUserDto: UpdateUserDto,
    performedBy: number,
    ip?: string,
  ): Promise<User> {
    const user = await this.findOne(id);
    const oldValue = { ...user };
    Object.assign(user, updateUserDto);
    const updatedUser = await this.userRepository.save(user);

    await this.actionLogsService.logAction({
      userId: performedBy,
      actionType: 'UPDATE',
      entityType: 'user',
      entityId: updatedUser.user_id,
      oldValue,
      newValue: updatedUser,
      ipAddress: ip,
    });

    return updatedUser;
  }

  async remove(id: number, performedBy: number, ip?: string): Promise<void> {
    const userForLog = await this.findOne(id);
    const userEntity = await this.userRepository.findOne({ where: { user_id: id } });
    if (!userEntity) {
      throw new NotFoundException('User not found');
    }

    await this.actionLogsService.logAction({
      userId: performedBy,
      actionType: 'DELETE',
      entityType: 'user',
      entityId: userEntity.user_id,
      oldValue: userForLog, 
      ipAddress: ip,
    });

    await this.userRepository.remove(userEntity);
  }

  // Métodos con auditoría
  async createWithAudit(
    createUserDto: CreateUserDto,
    performedBy: number,
    ip?: string,
  ): Promise<User> {
    const hashedPassword = await bcrypt.hash(createUserDto.password_hash, 10);
    createUserDto.password_hash = hashedPassword;

    const user = this.userRepository.create(createUserDto);
    const savedUser = await this.userRepository.save(user);

    await this.actionLogsService.logAction({
      userId: performedBy,
      actionType: 'CREATE',
      entityType: 'user',
      entityId: savedUser.user_id,
      newValue: savedUser,
      ipAddress: ip,
    });

    return savedUser;
  }

  async replace(
    id: number,
    replaceUserDto: ReplaceUserDto,
    performedBy: number,
    ip?: string,
  ): Promise<User> {
    const user = await this.findOne(id);
    const oldValue = { ...user };

    if (!replaceUserDto.email || replaceUserDto.email.trim() === '') {
      throw new BadRequestException('El email es obligatorio');
    }

    const updatedData = { ...replaceUserDto };
    if (replaceUserDto.password_hash) {
      updatedData.password_hash = await bcrypt.hash(replaceUserDto.password_hash, 10);
    }

    const newUser = this.userRepository.create({
      ...user,
      ...updatedData,
    });

    const replacedUser = await this.userRepository.save(newUser);

    await this.actionLogsService.logAction({
      userId: performedBy,
      actionType: 'UPDATE',
      entityType: 'User',
      entityId: replacedUser.user_id,
      oldValue,
      newValue: replacedUser,
      ipAddress: ip,
    });

    return replacedUser;
  }

  // Métodos de autenticación y activación
  async findByEmail(email: string): Promise<User | null> {
    return this.userRepository.findOne({ where: { email } });
  }

  async findByEmailWithPassword(email: string): Promise<User | null> {
    try {
      return await this.userRepository
        .createQueryBuilder('user')
        .addSelect(['user.email', 'user.password_hash'])
        .where('LOWER(user.email) = LOWER(:email)', { email })
        .getOne();
    } catch (error) {
      console.error('Error finding user by email:', error);
      return null;
    }
  }

  async findByActivationToken(token: string): Promise<User | null> {
    return this.userRepository.findOne({ where: { activation_token: token } });
  }

  async activateUser(token: string): Promise<User> {
    const user = await this.findByActivationToken(token);
    if (!user) {
      throw new NotFoundException('Token inválido');
    }
    user.is_active = true;
    user.activation_token = null;
    return this.userRepository.save(user); 
  }

  async activateUserByToken(activationToken: string): Promise<User> {
    const user = await this.findByActivationToken(activationToken);
    if (!user) {
      throw new NotFoundException('Token inválido');
    }
    user.is_active = true;
    user.activation_token = null;
    user.activated_at = new Date();
    return this.userRepository.save(user);
  }

  async confirmUser(activationToken: string): Promise<any> {
    const user = await this.findByActivationToken(activationToken);
    if (!user) {
      throw new NotFoundException('Token de activación inválido o expirado');
    }

    const updateUserDto: UpdateUserDto = {
      is_active: true,
      activation_token: null,
      activated_at: new Date(),
    };

    await this.update(user.user_id, updateUserDto, user.user_id);
    return {
      success: true,
      message: 'Usuario activado correctamente',
    };
  }

  // Métodos de búsqueda avanzada
  async findAllWithFilters(filters: {
    email?: string;
    createdStartDate?: string;
    createdEndDate?: string;
    updatedStartDate?: string;
    updatedEndDate?: string;
    is_active?: boolean;
  }): Promise<UsersView[]> {
    const query = this.usersViewRepository.createQueryBuilder('user');

    if (filters.email) {
      query.andWhere('LOWER(user.email) LIKE LOWER(:email)', { email: `%${filters.email}%` });
    }

    if (filters.createdStartDate && filters.createdEndDate) {
      query.andWhere('user.created_at BETWEEN :start AND :end', {
        start: filters.createdStartDate,
        end: filters.createdEndDate,
      });
    } else if (filters.createdStartDate || filters.createdEndDate) {
      throw new Error('Debe especificar ambas fechas para filtro por fecha de creación.');
    }

    if (filters.updatedStartDate && filters.updatedEndDate) {
      query.andWhere('user.updated_at BETWEEN :startUpdated AND :endUpdated', {
        startUpdated: filters.updatedStartDate,
        endUpdated: filters.updatedEndDate,
      });
    } else if (filters.updatedStartDate || filters.updatedEndDate) {
      throw new Error('Debe especificar ambas fechas para filtro por fecha de actualización.');
    }

    return query.orderBy('user.created_at', 'DESC').getMany();
  }
}