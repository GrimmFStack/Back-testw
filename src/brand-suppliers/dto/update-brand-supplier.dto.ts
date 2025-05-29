import { PartialType } from '@nestjs/mapped-types';
import { CreateBrandSupplierDto } from './create-brand-supplier.dto';
import { ApiPropertyOptional } from '@nestjs/swagger';

export class UpdateBrandSupplierDto extends PartialType(CreateBrandSupplierDto) {
  @ApiPropertyOptional({
    example: 'Nuevo Proveedor S.R.L.',
    description: 'Nombre completo del proveedor',
    maxLength: 100
  })
  name?: string;

  @ApiPropertyOptional({
    example: 'contacto@nuevoproveedor.com',
    description: 'Email único del proveedor',
    maxLength: 100
  })
  email?: string;
}