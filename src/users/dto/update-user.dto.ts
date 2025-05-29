// src/users/dto/update-user.dto.ts
import { IsBoolean, IsOptional, IsString, IsDate, IsUUID } from 'class-validator';

export class UpdateUserDto {
  @IsOptional()
  @IsBoolean()
  is_active?: boolean;

  @IsOptional()
  @IsString()
  activation_token?: string | null;

  @IsOptional()
  activated_at?: Date;
}
