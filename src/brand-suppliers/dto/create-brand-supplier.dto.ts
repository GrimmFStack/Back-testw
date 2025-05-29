import { IsEmail, IsNotEmpty, IsOptional, IsString, Length, IsBoolean } from 'class-validator';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

export class CreateBrandSupplierDto {
  @ApiProperty({
    example: 'Proveedor de Materiales Premium S.A.',
    description: 'Nombre completo del proveedor',
    maxLength: 100
  })
  @IsNotEmpty()
  @IsString()
  @Length(1, 100)
  name: string;

  @ApiPropertyOptional({
    example: 'Juan Pérez',
    description: 'Persona de contacto en el proveedor',
    maxLength: 100
  })
  @IsOptional()
  @IsString()
  @Length(1, 100)
  contactPerson?: string;

  @ApiProperty({
    example: 'contacto@proveedormaterials.com',
    description: 'Email único del proveedor',
    maxLength: 100
  })
  @IsNotEmpty()
  @IsEmail()
  @Length(1, 100)
  email: string;

  @ApiPropertyOptional({
    example: '9876543210',
    description: 'Teléfono de contacto (10 dígitos)',
    minLength: 10,
    maxLength: 15
  })
  @IsOptional()
  @IsString()
  @Length(10, 10)
  phone?: string;

  @ApiPropertyOptional({
    example: 'Av. Industrial 123, Lima, Perú',
    description: 'Dirección completa del proveedor'
  })
  @IsOptional()
  @IsString()
  address?: string;

  @ApiProperty({
    example: 1,
    description: 'ID de la marca a la que está asociado el proveedor'
  })
  @IsNotEmpty()
  brandId: number;

  @ApiPropertyOptional({
    example: true,
    description: 'Indica si el proveedor está activo',
    default: true
  })
  @IsOptional()
  @IsBoolean()
  isActive?: boolean;
}