import { ViewEntity, ViewColumn } from 'typeorm';

@ViewEntity({ name: 'brand_suppliers_view' })
export class BrandSupplierView {
  @ViewColumn()
  supplier_id: number;

  @ViewColumn()
  supplier_name: string;

  @ViewColumn()
  contact_person: string;

  @ViewColumn()
  email: string;

  @ViewColumn()
  phone: string;

  @ViewColumn()
  address: string;

  @ViewColumn()
  supplier_is_active: boolean;

  @ViewColumn()
  created_at: Date;

  @ViewColumn()
  updated_at: Date;

  @ViewColumn()
  brand_id: number;

  @ViewColumn()
  brand_name: string;
}
