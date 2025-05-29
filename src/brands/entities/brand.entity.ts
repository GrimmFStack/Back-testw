// src/brands/entities/brand.entity.ts
import { Entity, PrimaryGeneratedColumn, Column, OneToMany } from 'typeorm';
import { Product } from '../../products/entities/product.entity';
import { BrandSupplier } from '../../brand-suppliers/entities/brand-supplier.entity';


@Entity({ name: 'brands' })
export class Brand {
  @PrimaryGeneratedColumn({ name: 'brand_id' })
  id: number;

  @Column({ name: 'name' })
  name: string;

  @Column({ name: 'description', nullable: true })
  description?: string;

  @Column({ name: 'is_active', default: true })
  isActive: boolean;

  @Column({ name: 'created_at', type: 'date', default: () => 'CURRENT_DATE' })
  createdAt: Date;

  @Column({ name: 'updated_at', type: 'date', default: () => 'CURRENT_DATE' })
  updatedAt: Date;

  @OneToMany(() => Product, (product) => product.brand)
  products: Product[];

  @OneToMany(() => BrandSupplier, (supplier) => supplier.brand)
  suppliers: BrandSupplier[];
}