import { IsNotEmpty, IsOptional, IsString, IsBoolean } from 'class-validator';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

export class CreateBrandDto {
  @ApiProperty({
    example: 'NVIDIA',
    description: 'Nombre de la marca de TI',
    maxLength: 100
  })
  @IsNotEmpty()
  @IsString()
  name: string;

  @ApiPropertyOptional({
    example: 'Fabricante líder de GPUs y tecnología gráfica',
    description: 'Descripción de la marca'
  })
  @IsOptional()
  @IsString()
  description?: string;

  @ApiPropertyOptional({
    example: true,
    description: 'Indica si la marca está activa',
    default: true
  })
  @IsOptional()
  @IsBoolean()
  isActive?: boolean;
}