import { IsNotEmpty, IsOptional, IsString, IsNumber, IsBoolean } from 'class-validator';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

export class CreateProductDto {
  @ApiProperty({
    example: 'MBP-14',
    description: 'Código único del producto',
    maxLength: 50
  })
  @IsNotEmpty()
  @IsString()
  code: string;

  @ApiProperty({
    example: 'MacBook Pro 14"',
    description: 'Nombre del producto',
    maxLength: 100
  })
  @IsNotEmpty()
  @IsString()
  name: string;

  @ApiPropertyOptional({
    example: 'Laptop profesional con chip M1 Pro',
    description: 'Descripción detallada del producto'
  })
  @IsOptional()
  @IsString()
  description?: string;

  @ApiProperty({
    example: 32999,
    description: 'Precio del producto en la moneda base',
    minimum: 0
  })
  @IsNotEmpty()
  @IsNumber()
  price: number;

  @ApiProperty({
    example: 1,
    description: 'ID de la marca asociada al producto'
  })
  @IsNotEmpty()
  @IsNumber()
  brandId: number;

  @ApiPropertyOptional({
    example: true,
    description: 'Indica si el producto está activo',
    default: true
  })
  @IsOptional()
  @IsBoolean()
  isActive?: boolean;
}