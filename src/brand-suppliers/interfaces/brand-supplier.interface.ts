export interface BrandSupplier {
  supplierId: number;
  name: string;
  contactPerson?: string;
  email: string;
  phone?: string;
  address?: string;
  brandId: number;
  isActive: boolean;
  createdAt: Date;
  updatedAt: Date;
}