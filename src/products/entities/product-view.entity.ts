import { ViewEntity, ViewColumn } from 'typeorm';

@ViewEntity({ name: 'products_view' })
export class ProductView {
  @ViewColumn()
  product_id: number;

  @ViewColumn()
  code: string;

  @ViewColumn()
  product_name: string;

  @ViewColumn()
  description: string;

  @ViewColumn()
  price: number;

  @ViewColumn()
  product_is_active: boolean;

  @ViewColumn()
  created_at: Date;

  @ViewColumn()
  updated_at: Date;

  @ViewColumn()
  brand_id: number;

  @ViewColumn()
  brand_name: string;

  @ViewColumn()
  supplier_id: number;

  @ViewColumn()
  supplier_name: string;
}
