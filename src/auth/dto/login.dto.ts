// auth/dto/login.dto.ts
import { ApiProperty } from '@nestjs/swagger';
import { IsEmail, IsNotEmpty, IsString } from 'class-validator';

export class LoginDto {
  @ApiProperty({
    example: 'usuario@ejemplo.com',
    description: 'Email del usuario registrado'
  })
  @IsEmail()
  @IsNotEmpty()
  email: string;

  @ApiProperty({
    example: 'MiContraseñaSegura123!',
    description: 'Contraseña del usuario',
    minLength: 8
  })
  @IsString()
  @IsNotEmpty()
  password: string;
}