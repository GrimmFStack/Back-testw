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

  // auth.controller.ts
@Get('confirm/:token')
async confirmAccount(
  @Param('token') token: string,
  @Res() res: Response
) {
  try {
    const { accessToken } = await this.authService.confirmAccount(token);
    
    // Renderiza página simple con el token
    return res.send(`
      <!DOCTYPE html>
      <html>
      <head>
        <title>Cuenta Activada</title>
        <style>
          body { font-family: Arial; text-align: center; padding: 40px; }
          .token { 
            background: #f5f5f5; 
            padding: 15px; 
            margin: 20px auto;
            max-width: 500px;
            word-break: break-all;
          }
        </style>
      </head>
      <body>
        <h1>✅ Cuenta activada correctamente</h1>
        <p>Tu token de acceso es:</p>
        <div class="token">${accessToken}</div>
        <p>Copia este token para iniciar sesión en la aplicación</p>
      </body>
      </html>
    `);
    
  } catch (error) {
    return res.status(400).send(`
      <h1>❌ Error al activar la cuenta</h1>
      <p>${error.message}</p>
    `);
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