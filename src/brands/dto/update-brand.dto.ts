import { PartialType } from '@nestjs/mapped-types';
import { CreateBrandDto } from './create-brand.dto';
import { ApiPropertyOptional } from '@nestjs/swagger';

export class UpdateBrandDto extends PartialType(CreateBrandDto) {
  @ApiPropertyOptional({
    example: 'NVIDIA Corporation',
    description: 'Nombre actualizado de la marca'
  })
  name?: string;

  @ApiPropertyOptional({
    example: 'Líder en tecnología GPU e inteligencia artificial',
    description: 'Descripción actualizada'
  })
  description?: string;
}