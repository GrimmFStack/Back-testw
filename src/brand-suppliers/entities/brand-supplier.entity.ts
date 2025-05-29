// src/brand-suppliers/entities/brand-supplier.entity.ts
import { Entity, PrimaryGeneratedColumn, Column, ManyToOne, JoinColumn } from 'typeorm';
import { Brand } from '../../brands/entities/brand.entity';
import { User } from '../../users/entities/user.entity';

@Entity({ name: 'brand_suppliers' })
export class BrandSupplier {
  @PrimaryGeneratedColumn({ name: 'supplier_id' })
  id: number; // Changed from supplierId to id to match Brand entity pattern

  @Column({ name: 'name' })
  name: string;

  @Column({ name: 'contact_person', nullable: true })
  contactPerson?: string;

  @Column({ name: 'email' })
  email: string;

  @Column({ name: 'phone', nullable: true })
  phone?: string;

  @Column({ name: 'address', nullable: true })
  address?: string;

  @Column({ name: 'is_active', default: true })
  isActive: boolean;

  @Column({ name: 'created_at', type: 'date', default: () => 'CURRENT_DATE' })
  createdAt: Date;

  @Column({ name: 'updated_at', type: 'date', default: () => 'CURRENT_DATE' })
  updatedAt: Date;

  @ManyToOne(() => Brand, (brand) => brand.suppliers)
  @JoinColumn({ name: 'brand_id' })
  brand: Brand;

  @Column({ name: 'brand_id' })
  brandId: number;
}