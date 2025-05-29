import { ApiProperty } from '@nestjs/swagger';

export class ProductViewDto {
  @ApiProperty()
  product_id: number;

  @ApiProperty()
  code: string;

  @ApiProperty()
  product_name: string;

  @ApiProperty()
  description: string;

  @ApiProperty()
  price: number;

  @ApiProperty()
  created_at: Date;

  @ApiProperty()
  updated_at: Date;

  @ApiProperty()
  brand_id: number;

  @ApiProperty()
  brand_name: string;

  @ApiProperty()
  supplier_id: number;

  @ApiProperty()
  supplier_name: string;
}
