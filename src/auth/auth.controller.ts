import {
  Controller,
  Post,
  Body,
  Get,
  HttpStatus,
  HttpCode,
  Req,
  UseGuards,
  UnauthorizedException,
  Param, BadRequestException
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { UserService } from '../users/users.service';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';
import { Request } from 'express';
import {
  ApiTags,
  ApiOperation,
  ApiResponse,
  ApiBody,
  ApiBearerAuth,
  ApiParam
} from '@nestjs/swagger';
import { JwtAuthGuard } from './jwt-auth.guard';
import { formatResponse } from '../common/utils/response-format';

@ApiTags('Auth')
@Controller('auth')
export class AuthController {
  constructor(
    private readonly authService: AuthService,
    private readonly userService: UserService,
  ) {}


  @UseGuards(JwtAuthGuard)
  @Post('logout')
  @HttpCode(200)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Cerrar sesión' })
  async logout(@Req() req: Request) {
    const authHeader = req.headers.authorization || '';
    const token = authHeader.replace('Bearer ', '');

    if (!token) {
      throw new UnauthorizedException('Token no proporcionado');
    }

    await this.authService.logout(token);
    return formatResponse([{ message: 'Sesión cerrada correctamente' }]);
  }

  @Post('register')
  @HttpCode(HttpStatus.CREATED)
  @ApiOperation({ summary: 'Registrar nuevo usuario (envía correo de confirmación)' }) 
  @ApiBody({ type: RegisterDto })
  @ApiResponse({
    status: HttpStatus.CREATED,
    description: 'Usuario registrado exitosamente',
    schema: {
      example: {
        user_id: 1,
        username: 'nuevousuario',
        email: 'usuario@ejemplo.com',
        is_active: true,
        created_at: '2023-08-01T12:00:00Z',
        updated_at: '2023-08-01T12:00:00Z',
      },
    },
  })
  @ApiResponse({
    status: HttpStatus.BAD_REQUEST,
    description: 'Error en la validación de datos',
  })
  @ApiResponse({
    status: HttpStatus.CONFLICT,
    description: 'El email ya está registrado',
  })
  async register(@Body() registerDto: RegisterDto) {
  return this.authService.register(registerDto); 
}

@Get('confirm/:activationToken')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Confirmar cuenta con token de activación' })
  @ApiParam({ name: 'activationToken', description: 'Token de activación enviado por email' })
  @ApiResponse({
    status: HttpStatus.OK,
    description: 'Cuenta activada correctamente',
  })
  @ApiResponse({
    status: HttpStatus.BAD_REQUEST,
    description: 'Token inválido o expirado',
  })
  async confirmAccount(@Param('activationToken') activationToken: string) {
    try {
      const message = await this.authService.confirmAccount(activationToken);
      return formatResponse([{ message }]);
    } catch (error) {
      throw new BadRequestException(error.message || 'Token inválido o expirado');
    }
  }


  @Post('login')
@HttpCode(HttpStatus.OK)
@ApiOperation({ summary: 'Autenticación de usuario' })
@ApiBody({
  type: LoginDto,
  examples: { 
    example1: {
      summary: 'Ejemplo de login',
      value: {
        email: 'usuario@ejemplo.com',
        password: 'PasswordSeguro123!',
      },
    },
  },
})
@ApiResponse({
  status: HttpStatus.OK,
  schema: {
    example: {
      expires_in: 3600,
      login_token: 'tokenEjemplo',
    },
  },
})
@ApiResponse({
  status: HttpStatus.UNAUTHORIZED,
  description: 'Credenciales inválidas',
})
@ApiResponse({
  status: HttpStatus.FORBIDDEN,
  description: 'Cuenta desactivada',
})
async login(@Body() loginDto: LoginDto) {
  return this.authService.login(loginDto);
}
}
