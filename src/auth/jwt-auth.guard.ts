import {
  Injectable,
  ExecutionContext,
  UnauthorizedException,
} from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { AuthService } from './auth.service';

@Injectable()
export class JwtAuthGuard extends AuthGuard('jwt') {
  constructor(private readonly authService: AuthService) {
    super();
  }

  async canActivate(context: ExecutionContext): Promise<boolean> {
  const req = context.switchToHttp().getRequest();
  const authHeader = req.headers.authorization || '';
  const token = authHeader.replace(/^Bearer\s+/i, '').trim();

  console.log('[guard] Token recibido para validar:', token);

  if (!token) {
    throw new UnauthorizedException('Token no proporcionado');
  }

  const can = (await super.canActivate(context)) as boolean;
  console.log('[guard] Resultado super.canActivate:', can);
  if (!can) return false;

  const isBlacklisted = await this.authService.isBlacklisted(token);
  console.log('[guard] ¿Token en blacklist?', isBlacklisted);

  if (isBlacklisted) {
    throw new UnauthorizedException('Token en lista negra o sesión cerrada');
  }

  return true;
}

  handleRequest(err: any, user: any, info: any, context: ExecutionContext) {
    if (err || !user) {
      throw err || new UnauthorizedException('Token inválido');
    }
    return user;
  }
}
