// src/products/dto/update-product.ts
import { IsOptional, IsString, IsNumber, IsBoolean } from 'class-validator';
import { ApiPropertyOptional } from '@nestjs/swagger';

export class UpdateProductDto {
  @ApiPropertyOptional({
    example: 'IP13-128',
    description: 'Código único del producto',
  })
  @IsOptional()
  @IsString()
  code?: string;

  @ApiPropertyOptional({
    example: 'iPhone 13 128GB',
    description: 'Nombre del producto',
  })
  @IsOptional()
  @IsString()
  name?: string;

  @ApiPropertyOptional({
    example: 'Smartphone con chip A15 Bionic',
    description: 'Descripción detallada del producto',
  })
  @IsOptional()
  @IsString()
  description?: string;

  @ApiPropertyOptional({
    example: 17999,
    description: 'Precio del producto en la moneda base',
    type: Number,
  })
  @IsOptional()
  @IsNumber()
  price?: number;

  @ApiPropertyOptional({
    example: 1,
    description: 'ID de la marca a la que pertenece el producto',
    type: Number,
  })
  @IsOptional()
  @IsNumber()
  brandId?: number;

  @ApiPropertyOptional({
    example: true,
    description: 'Indica si el producto está activo',
    type: Boolean,
  })
  @IsOptional()
  @IsBoolean()
  isActive?: boolean;
}