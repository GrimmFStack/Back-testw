// src/products/products.service.ts
import { Injectable, NotFoundException, ConflictException, BadRequestException, ForbiddenException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository, Between, Like, In } from 'typeorm';
import { Product } from './entities/product.entity';
import { CreateProductDto } from './dto/create-product.dto';
import { UpdateProductDto } from './dto/update-product.dto';
import { ActionLogsService } from '../action-logs/action-logs.service';
import { User } from '../users/entities/user.entity';
import { Brand } from '../brands/entities/brand.entity';
import { ProductSearchDto } from './dto/product-search.dto';
import { ProductView } from './entities/product-view.entity';

@Injectable()
export class ProductsService {
  constructor(
    @InjectRepository(Product)
    private productRepository: Repository<Product>,
    @InjectRepository(Brand)
    private brandRepository: Repository<Brand>,
    private actionLogsService: ActionLogsService,
    @InjectRepository(ProductView)
    private productViewRepository: Repository<ProductView>,
  ) {}

  private async validateBrand(brandId: number): Promise<Brand> {
    const brand = await this.brandRepository.findOne({ 
      where: { id: brandId } 
    });
    
    if (!brand) {
      throw new BadRequestException(`Brand with ID ${brandId} not found`);
    }
    
    if (!brand.isActive) {
      throw new ForbiddenException(`Cannot add/update products for inactive brand (ID: ${brandId})`);
    }
    
    return brand;
  }

//   async searchProducts(filters: ProductSearchDto): Promise<Product[]> {
//     const where: any = {};
//     const relations = ['brand'];

//     // Filtro de búsqueda general
//     if (filters.searchTerm) {
//       where.name = Like(`%${filters.searchTerm}%`);
//       where.code = Like(`%${filters.searchTerm}%`);
//       where.description = Like(`%${filters.searchTerm}%`);
//     }

//     // Filtro por fechas de creación (convertimos strings a Date)
//     if (filters.creationStartDate && filters.creationEndDate) {
//       where.createdAt = Between(
//         new Date(filters.creationStartDate),
//         new Date(filters.creationEndDate)
//       );
//     } else if (filters.creationStartDate) {
//       where.createdAt = new Date(filters.creationStartDate);
//     }

//     // Filtro por estado activo/inactivo
//     if (typeof filters.isActive !== 'undefined') {
//       where.isActive = filters.isActive;
//     }

//     // Filtro por marcas
//     if (filters.brandIds && filters.brandIds.length > 0) {
//       where.brand = { id: In(filters.brandIds) };
//     }

//     return this.productRepository.find({
//       where,
//       relations,
//       order: { createdAt: 'DESC' }
//     });
// }

 async findAll(filters: {
  search?: string;
  createdStartDate?: string;
  createdEndDate?: string;
  updatedStartDate?: string;
  updatedEndDate?: string;
  isActive?: boolean;
  brandIds?: number[];
  supplierIds?: number[];
}) {
  const query = this.productViewRepository.createQueryBuilder('product');
  const today = new Date();

  // Validación y filtro por fecha de creación
  if (filters.createdStartDate || filters.createdEndDate) {
    if (!filters.createdStartDate || !filters.createdEndDate) {
      throw new BadRequestException('Debe especificar tanto fecha de inicio como de fin para la búsqueda por creación.');
    }

    const createdStart = new Date(filters.createdStartDate);
    const createdEnd = new Date(filters.createdEndDate);

    if (createdStart > createdEnd) {
      throw new BadRequestException('La fecha de inicio de creación no puede ser mayor que la fecha de fin.');
    }

    if (createdStart > today || createdEnd > today) {
      throw new BadRequestException('No se puede buscar productos creados en el futuro.');
    }

    query.andWhere(`DATE(product.created_at) BETWEEN :createdStart AND :createdEnd`, {
      createdStart: filters.createdStartDate,
      createdEnd: filters.createdEndDate,
    });
  }

  // Validación y filtro por fecha de actualización
  if (filters.updatedStartDate || filters.updatedEndDate) {
    if (!filters.updatedStartDate || !filters.updatedEndDate) {
      throw new BadRequestException('Debe especificar tanto fecha de inicio como de fin para la búsqueda por edición.');
    }

    const updatedStart = new Date(filters.updatedStartDate);
    const updatedEnd = new Date(filters.updatedEndDate);

    if (updatedStart > updatedEnd) {
      throw new BadRequestException('La fecha de inicio de edición no puede ser mayor que la fecha de fin.');
    }

    if (updatedStart > today || updatedEnd > today) {
      throw new BadRequestException('No se puede buscar productos editados en el futuro.');
    }

    query.andWhere(`DATE(product.updated_at) BETWEEN :updatedStart AND :updatedEnd`, {
      updatedStart: filters.updatedStartDate,
      updatedEnd: filters.updatedEndDate,
    });
  }

  // Búsqueda general
  if (filters.search) {
    query.andWhere(
      `(product.code ILIKE :search OR product.product_name ILIKE :search OR product.description ILIKE :search OR product.brand_name ILIKE :search OR product.supplier_name ILIKE :search)`,
      { search: `%${filters.search}%` }
    );
  }

  // Filtro por estado
  if (filters.isActive !== undefined) {
    query.andWhere(`product.product_is_active = :isActive`, { isActive: filters.isActive });
  }

  // Filtro por marcas
  if (filters.brandIds?.length) {
    query.andWhere('product.brand_id IN (:...brandIds)', { brandIds: filters.brandIds });
  }

  // Filtro por proveedores
  if (filters.supplierIds?.length) {
    query.andWhere('product.supplier_id IN (:...supplierIds)', { supplierIds: filters.supplierIds });
  }

  return query
  .orderBy('product.created_at', 'DESC')
  .getMany();
}

  async findOne(id: number): Promise<Product> {
    const product = await this.productRepository.findOne({ 
      where: { id },
      relations: ['brand'],
    });

    if (!product) {
      throw new NotFoundException(`Product with ID ${id} not found`);
    }
    return product;
  }

  async create(createProductDto: CreateProductDto, user: User): Promise<Product> {
    const brand = await this.validateBrand(createProductDto.brandId);

    try {
      const product = this.productRepository.create({
        ...createProductDto,
        brand,
        isActive: true,
      });

      const savedProduct = await this.productRepository.save(product);

      await this.actionLogsService.logAction({
        userId: user.user_id,
        actionType: 'CREATE',
        entityType: 'Product',
        entityId: savedProduct.id,
        newValue: savedProduct,
      });

      return savedProduct;
    } catch (error) {
      if (error.code === '23505') {
        throw new ConflictException('Product code already exists');
      }
      throw error;
    }
  }

  async update(id: number, updateProductDto: UpdateProductDto, user: User): Promise<Product> {
    const product = await this.findOne(id);
    const oldValues = { ...product };

    if (updateProductDto.brandId) {
      const brand = await this.validateBrand(updateProductDto.brandId);
      product.brand = brand;
    }

    try {
      Object.assign(product, updateProductDto);
      product.updatedAt = new Date();
      
      const updatedProduct = await this.productRepository.save(product);

      await this.actionLogsService.logAction({
        userId: user.user_id,
        actionType: 'UPDATE',
        entityType: 'Product',
        entityId: updatedProduct.id,
        oldValue: oldValues,
        newValue: updatedProduct,
      });

      return updatedProduct;
    } catch (error) {
      if (error.code === '23505') {
        throw new ConflictException('Product code already exists');
      }
      throw error;
    }
  }

  async deactivate(id: number, user: User): Promise<Product> {
    const product = await this.findOne(id);
    product.isActive = false;
    product.updatedAt = new Date();
    
    await this.actionLogsService.logAction({
      userId: user.user_id,
      actionType: 'DEACTIVATE',
      entityType: 'Product',
      entityId: product.id,
      oldValue: { isActive: true },
      newValue: { isActive: false },
    });

    return this.productRepository.save(product);
  }

  async activate(id: number, user: User): Promise<Product> {
    const product = await this.findOne(id);
    product.isActive = true;
    product.updatedAt = new Date();
    
    await this.actionLogsService.logAction({
      userId: user.user_id,
      actionType: 'ACTIVATE',
      entityType: 'Product',
      entityId: product.id,
      oldValue: { isActive: false },
      newValue: { isActive: true },
    });

    return this.productRepository.save(product);
  }
   async findOneFromView(productId: number): Promise<ProductView> {
    const product = await this.productViewRepository.findOne({
      where: { product_id: productId },
    });

    if (!product) {
      throw new NotFoundException(`Producto con ID ${productId} no encontrado`);
    }

    return product;
  }
  async findOneMinimal(id: number) {
  return this.productViewRepository.findOne({
    where: { product_id: id },
    select: [
      'product_id',
      'code',
      'product_name',
      'description',
      'price',
      'product_is_active',
      'brand_name',
      'supplier_name'
    ]
  });
}
}
