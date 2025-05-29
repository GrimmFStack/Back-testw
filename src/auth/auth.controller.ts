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
  Param,
  BadRequestException,
  Res,
  Inject
} from '@nestjs/common';
import { Response, Request } from 'express';
import { AuthService } from './auth.service';
import { UserService } from '../users/users.service';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';
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
import { ConfigService } from '@nestjs/config';

@ApiTags('Auth')
@Controller('auth')
export class AuthController {
  constructor(
    private readonly authService: AuthService,
    private readonly userService: UserService,
    @Inject(ConfigService)
    private readonly configService: ConfigService,
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
        is_active: false,
        created_at: '2023-08-01T12:00:00Z',
        updated_at: '2023-08-01T12:00:00Z',
        message: 'Email de confirmación enviado'
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

  @Get('confirm/:token')
  @ApiOperation({ summary: 'Confirmar cuenta con token' })
  @ApiParam({ name: 'token', type: String })
  async confirmAccount(
    @Param('token') token: string,
    @Res() res: Response
  ) {
    try {
      const result = await this.authService.confirmAccount(token);
      
      return res.render('confirmation-success', {
        token: result.accessToken,
        appName: this.configService.get('APP_NAME'),
        supportEmail: this.configService.get('SUPPORT_EMAIL')
      });
      
    } catch (error) {
      return res.render('confirmation-error', {
        error: error.message,
        appName: this.configService.get('APP_NAME'),
        supportEmail: this.configService.get('SUPPORT_EMAIL'),
        retryUrl: `${this.configService.get('FRONTEND_URL')}/resend-activation`
      });
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
        access_token: 'tokenEjemplo',
        user_id: 1,
        email: 'usuario@ejemplo.com'
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