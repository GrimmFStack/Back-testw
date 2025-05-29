import { IsOptional, IsBoolean, IsArray, IsNumber, IsString } from 'class-validator';

export class ProductSearchDto {
  @IsOptional()
  @IsString()
  searchTerm?: string;

  @IsOptional()
  @IsString()
  creationStartDate?: string;  // Mantenemos como string para recibir del query

  @IsOptional()
  @IsString()
  creationEndDate?: string;    // Mantenemos como string para recibir del query

  @IsOptional()
  @IsString()
  updateStartDate?: string;    // Añadido para coincidir con el controlador

  @IsOptional()
  @IsString()
  updateEndDate?: string;      // Añadido para coincidir con el controlador

  @IsOptional()
  @IsBoolean()
  isActive?: boolean;

  @IsOptional()
  @IsArray()
  @IsNumber({}, { each: true })
  brandIds?: number[];
}