import {
  Injectable,
  UnauthorizedException,
  ConflictException,
  InternalServerErrorException,
  Inject,
  forwardRef,
  ForbiddenException
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository, Like } from 'typeorm';
import { UserService } from '../users/users.service';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';
import { User } from '../users/entities/user.entity';
import { BlacklistedToken } from './entities/blacklisted-token.entity';
import { MailService } from '../mail/mail.service';
import { ApiTags, ApiOperation, ApiResponse, ApiBody, ApiBearerAuth } from '@nestjs/swagger';

@Injectable()
export class AuthService {
  private readonly SALT_ROUNDS = 12;

  constructor(
    @Inject(forwardRef(() => UserService))
    private readonly usersService: UserService,
    private readonly jwtService: JwtService,
    private readonly mailService: MailService,
    @InjectRepository(BlacklistedToken)
    private readonly blacklistedTokenRepo: Repository<BlacklistedToken>,
  ) {}


  async isBlacklisted(token: string): Promise<boolean> {
  const cleanedToken = token.replace(/^Bearer\s+/i, '').trim();

  if (!cleanedToken) {
    console.warn('[isBlacklisted] Token vacío después de limpiar. Se considera inválido.');
    return true;
  }

  console.log('[isBlacklisted] Buscando token exacto:', cleanedToken);

  const entry = await this.blacklistedTokenRepo.findOneBy({ token: cleanedToken });

  if (entry) {
    console.log('[isBlacklisted] Entrada encontrada en blacklist:', entry);
  } else {
    console.log('[isBlacklisted] Token no está en blacklist.');
  }

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

    const activationToken = crypto.randomUUID(); // o usa un generador seguro

    await this.usersService.create({
      email: normalizedEmail,
      password_hash: hashedPassword,
      is_active: false,
      activation_token: activationToken,
    });

    await this.mailService.sendConfirmationEmail(normalizedEmail, activationToken);

    return {
      success: true,
      message: 'Usuario registrado. Por favor revisa tu correo para confirmar tu cuenta.',
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
        access_token: token
      }]);
    } catch (error) {
      console.error('Error en login:', error);

      if (error instanceof UnauthorizedException) {
        throw new UnauthorizedException('Email o contraseña incorrectos');
      }

      throw new InternalServerErrorException('Error al iniciar sesión');
    }
  }

  private normalizeToken(token: string): string {
  return token.replace(/^Bearer\s+/i, '').trim();
}

async logout(token: string): Promise<any> {
  const normalizedToken = token.replace(/^Bearer\s+/i, '').trim();

  console.log('[logout] Token normalizado:', normalizedToken);

  const decoded: any = this.jwtService.decode(normalizedToken);
  if (!decoded || !decoded.sub) {
    throw new UnauthorizedException('Token inválido');
  }

  const user = await this.usersService.findOne(decoded.sub);
  if (!user) {
    throw new UnauthorizedException('Usuario no encontrado');
  }

  const expiresAt = new Date(decoded.exp * 1000);

  await this.blacklistedTokenRepo.save({
    token: normalizedToken,
    expiresAt,
    user,
  });

  console.log('[logout] Token guardado en blacklist');

  return formatResponse([{ message: 'Sesión cerrada correctamente' }]);
}

async confirmAccount(activationToken: string): Promise<any> {
  return this.usersService.confirmUser(activationToken);
}


  private async validateUser(email: string, password: string): Promise<User> {
  if (!email || !password) {
    throw new UnauthorizedException('Se requieren email y contraseña');
  }

  const user = await this.usersService.findByEmailWithPassword(email);
  if (!user) {
    throw new UnauthorizedException('Credenciales inválidas');
  }

  if (!user.is_active) {
    throw new ForbiddenException('La cuenta está desactivada');
  }

  const isValidPassword = await this.comparePasswords(password, user.password_hash);
  if (!isValidPassword) {
    throw new UnauthorizedException('Credenciales inválidas');
  }

  return user;
}


  private async hashPassword(password: string): Promise<string> {
    const salt = await bcrypt.genSalt(this.SALT_ROUNDS);
    return await bcrypt.hash(password, salt);
  }

  private async comparePasswords(plainTextPassword: string, hash: string): Promise<boolean> {
    if (!plainTextPassword || !hash) return false;

    if (!this.isValidBcryptHash(hash)) {
      return plainTextPassword === hash;
    }

    return await bcrypt.compare(plainTextPassword, hash);
  }

  private isValidBcryptHash(hash: string): boolean {
    return hash.startsWith('$2a$') || hash.startsWith('$2b$') || hash.startsWith('$2y$');
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