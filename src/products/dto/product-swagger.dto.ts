import { ApiProperty } from '@nestjs/swagger';

export class ProductSwaggerDto {
  @ApiProperty({ example: 12 })
  product_id: number;

  @ApiProperty({ example: 'XBOX-X' })
  code: string;

  @ApiProperty({ example: 'Xbox Series X' })
  product_name: string;

  @ApiProperty({ example: 'Consola de juegos 4K con 1TB SSD y GPU de 12 TFLOPS' })
  description: string;
  
  @ApiProperty({ example: 12999.00 })
  price: number;

  @ApiProperty({ example: true })
  is_active: boolean;

  @ApiProperty({ example: 'Microsoft' })
  brand_name: string;

  @ApiProperty({ example: 'Cloud Systems Inc' })
  supplier_name: string;
}