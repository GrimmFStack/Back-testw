import {
  Injectable,
  UnauthorizedException,
  ConflictException,
  InternalServerErrorException,
  Inject,
  forwardRef,
  ForbiddenException,
  BadRequestException,
  NotFoundException
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { UserService } from '../users/users.service';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';
import { User } from '../users/entities/user.entity';
import { BlacklistedToken } from './entities/blacklisted-token.entity';
import { MailService } from '../mail/mail.service';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class AuthService {
  private readonly SALT_ROUNDS = 12;

  constructor(
    @Inject(forwardRef(() => UserService))
    private readonly usersService: UserService,
    private readonly jwtService: JwtService,
    private readonly mailService: MailService,
    private readonly configService: ConfigService,
    @InjectRepository(BlacklistedToken)
    private readonly blacklistedTokenRepo: Repository<BlacklistedToken>,
  ) {}

  async isBlacklisted(token: string): Promise<boolean> {
    const cleanedToken = this.normalizeToken(token);
    
    if (!cleanedToken) {
      console.warn('[isBlacklisted] Token vacío después de limpiar');
      return true;
    }

    const entry = await this.blacklistedTokenRepo.findOneBy({ token: cleanedToken });
    return !!entry;
  }

  async register(registerDto: RegisterDto): Promise<any> {
    const { email, password } = registerDto;
    
    if (!email || !password) {
      throw new UnauthorizedException('Se requieren email y contraseña');
    }

    if (password.length < 8) {
      throw new UnauthorizedException('La contraseña debe tener al menos 8 caracteres');
    }

    const normalizedEmail = email.toLowerCase().trim();
    const existingUser = await this.usersService.findByEmail(normalizedEmail);
    
    if (existingUser) {
      throw new ConflictException('El email ya está registrado');
    }

    try {
      const hashedPassword = await this.hashPassword(password);
      const activationToken = this.jwtService.sign(
        { email: normalizedEmail },
        { 
          secret: this.configService.get('JWT_ACTIVATION_SECRET'),
          expiresIn: '24h' 
        }
      );

      const user = await this.usersService.create({
        email: normalizedEmail,
        password_hash: hashedPassword,
        is_active: false,
        activation_token: activationToken  // Cambiado a activation_token para coincidir con tu UserService
      });

      await this.mailService.sendConfirmationEmail(
        normalizedEmail, 
        activationToken
      );

      return {
        success: true,
        message: 'Usuario registrado. Por favor revisa tu correo para confirmar tu cuenta.',
        userId: user.user_id
      };
    } catch (error) {
      console.error('Error en registro:', error);
      throw new InternalServerErrorException('Error al crear el usuario');
    }
  }

  async login(loginDto: LoginDto): Promise<any> {
    try {
      const normalizedEmail = loginDto.email.toLowerCase().trim();
      const user = await this.validateUser(normalizedEmail, loginDto.password);

      const payload = {
        sub: user.user_id,
        email: user.email,
        is_active: user.is_active,
      };

      const token = this.jwtService.sign(payload);

      return formatResponse([{
        access_token: token,
        userId: user.user_id,
        email: user.email
      }]);
    } catch (error) {
      console.error('Error en login:', error);
      throw new UnauthorizedException('Email o contraseña incorrectos');
    }
  }

  async logout(token: string): Promise<any> {
    const normalizedToken = this.normalizeToken(token);
    const decoded: any = this.jwtService.decode(normalizedToken);
    
    if (!decoded || !decoded.sub) {
      throw new UnauthorizedException('Token inválido');
    }

    const user = await this.usersService.findOne(decoded.sub);  // Cambiado a findOne
    if (!user) {
      throw new UnauthorizedException('Usuario no encontrado');
    }

    const expiresAt = new Date(decoded.exp * 1000);

    await this.blacklistedTokenRepo.save({
      token: normalizedToken,
      expiresAt,
      user,
    });

    return formatResponse([{ message: 'Sesión cerrada correctamente' }]);
  }

  async confirmAccount(activationToken: string): Promise<string> {
    try {
      const { email } = this.jwtService.verify(activationToken, {
        secret: this.configService.get('JWT_ACTIVATION_SECRET')
      });

      const user = await this.usersService.findByEmail(email);
      if (!user || user.activation_token !== activationToken) {
        throw new NotFoundException('Token inválido');
      }

      await this.usersService.activateUserByToken(activationToken);  // Usando el método correcto
      return 'Cuenta activada exitosamente';
    } catch (error) {
      console.error('Error en confirmación:', error);
      throw new BadRequestException('Token de activación inválido o expirado');
    }
  }

  private async validateUser(email: string, password: string): Promise<User> {
    const user = await this.usersService.findByEmailWithPassword(email);
    
    if (!user) {
      throw new UnauthorizedException('Credenciales inválidas');
    }

    if (!user.is_active) {
      throw new ForbiddenException('La cuenta no está activada. Por favor verifica tu email.');
    }

    const isValidPassword = await this.comparePasswords(password, user.password_hash);
    if (!isValidPassword) {
      throw new UnauthorizedException('Credenciales inválidas');
    }

    return user;
  }

  private normalizeToken(token: string): string {
    return token.replace(/^Bearer\s+/i, '').trim();
  }

  private async hashPassword(password: string): Promise<string> {
    const salt = await bcrypt.genSalt(this.SALT_ROUNDS);
    return bcrypt.hash(password, salt);
  }

  private async comparePasswords(plainTextPassword: string, hash: string): Promise<boolean> {
    if (!plainTextPassword || !hash) return false;
    return bcrypt.compare(plainTextPassword, hash);
  }
}

function formatResponse(records: any[]): any {
  return {
    success: true,
    data: {
      records,
      total_count: records.length,
    },
  };
}