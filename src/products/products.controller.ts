import { Controller, Get, Post, Body, Param, Put, Delete, Query, UseGuards, UnauthorizedException, BadRequestException, NotFoundException } from '@nestjs/common';
import { ProductsService } from './products.service';
import { CreateProductDto } from './dto/create-product.dto';
import { UpdateProductDto } from './dto/update-product.dto';
import { ApiTags, ApiBearerAuth, ApiOperation, ApiResponse, ApiParam, ApiQuery } from '@nestjs/swagger';
import { Product } from './entities/product.entity';
import { CurrentUser } from '../auth/decorators/current-user-decorator';
import { User } from '../users/entities/user.entity';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { ParseIntPipe } from '@nestjs/common';
import { ApiOkResponse, ApiNotFoundResponse } from '@nestjs/swagger';
import { ProductView } from './entities/product-view.entity';
import { plainToInstance } from 'class-transformer';
import { ProductSwaggerDto } from './dto/product-swagger.dto';

@ApiTags('Productos')
@ApiBearerAuth()
@UseGuards(JwtAuthGuard)
@Controller('products')
export class ProductsController {
  constructor(private readonly productsService: ProductsService) {}

@Get('view/:id')
@ApiOperation({ summary: 'Obtener producto por ID' })
@ApiParam({
  name: 'id',
  type: Number,
  description: 'ID del producto',
  example: 12,
})
@ApiResponse({
  status: 200,
  description: 'Producto encontrado',
  schema: {
    example: {
      product_id: 12,
      code: 'XBOX-X',
      product_name: 'Xbox Series X',
      description: 'Consola de juegos 4K con 1TB SSD y GPU de 12 TFLOPS',
      price: 12999.00,
      is_active: 'Sí',
      brand_name: 'Microsoft',
      supplier_name: 'Cloud Systems Inc'
    }
  }
})
@ApiResponse({ status: 400, description: 'ID inválido' })
@ApiResponse({ status: 404, description: 'Producto no encontrado' })
async findOneFromView(@Param('id') id: string) {
  if (isNaN(+id)) {
    throw new BadRequestException('ID inválido');
  }

  const product = await this.productsService.findOneMinimal(+id);
  
  if (!product) {
    throw new NotFoundException('Producto no encontrado');
  }

  return {
    product_id: product.product_id,
    code: product.code,
    product_name: product.product_name,
    description: product.description,
    price: product.price,
    is_active: product.product_is_active ? 'Sí' : 'No', 
    brand_name: product.brand_name,
    supplier_name: product.supplier_name
  };
}

@Get()
@ApiOperation({ 
  summary: 'Buscar productos con filtros combinados',
  description: 'Permite buscar productos por múltiples criterios. Todos los parámetros son opcionales.'
})
@ApiQuery({ 
  name: 'search', 
  required: false, 
  description: 'Texto para buscar en código, nombre o descripción de producto o nombre de marca o proveedor',
  example: 'iPhone'
})
@ApiQuery({ 
  name: 'createdStartDate', 
  required: false,  
  description: 'Fecha inicial de creación (formato YYYY-MM-DD)',
  example: '2023-01-01'
})
@ApiQuery({ 
  name: 'createdEndDate', 
  required: false, 
  description: 'Fecha final de creación (formato YYYY-MM-DD)',
  example: '2023-12-31'
})
@ApiQuery({ 
  name: 'updatedStartDate', 
  required: false, 
  description: 'Fecha inicial de actualización (formato YYYY-MM-DD)',
  example: '2023-01-01'
})
@ApiQuery({ 
  name: 'updatedEndDate', 
  required: false, 
  description: 'Fecha final de actualización (formato YYYY-MM-DD)',
  example: '2023-12-31'
})
@ApiQuery({ 
  name: 'isActive', 
  required: false, 
  description: 'Filtrar por estado activo (true) o inactivo (false)',
  example: true
})
@ApiQuery({ 
  name: 'brandIds', 
  required: false, 
  description: 'IDs de marcas separados por comas',
  example: '1,2,3'
})
@ApiQuery({ 
  name: 'supplierIds', 
  required: false, 
  description: 'IDs de proveedores separados por comas',
  example: '5,9'
})
@ApiResponse({
  status: 200,
  description: 'Lista de productos encontrados',
  type: [Product]
})
@ApiResponse({ 
  status: 401, 
  description: 'No autorizado - Token inválido o no proporcionado'
})
async findAll(
  @Query('search') search: string,
  @Query('createdStartDate') createdStartDate: string,
  @Query('createdEndDate') createdEndDate: string,
  @Query('updatedStartDate') updatedStartDate: string,
  @Query('updatedEndDate') updatedEndDate: string,
  @Query('isActive') isActive: string,
  @Query('brandIds') brandIds: string,
  @Query('supplierIds') supplierIds: string,
  @CurrentUser() user: User
) {
  if (!user) {
    throw new UnauthorizedException('Token inválido o no proporcionado');
  }

  const now = new Date();

  // Validación fechas de creación
  if ((createdStartDate && !createdEndDate) || (!createdStartDate && createdEndDate)) {
    throw new BadRequestException('Debe proporcionar ambas fechas de creación: createdStartDate y createdEndDate');
  }
  if (createdStartDate && createdEndDate) {
    const start = new Date(createdStartDate);
    const end = new Date(createdEndDate);

    if (isNaN(start.getTime()) || isNaN(end.getTime())) {
      throw new BadRequestException('Fechas de creación inválidas, formato esperado YYYY-MM-DD');
    }
    if (start > end) {
      throw new BadRequestException('createdStartDate no puede ser mayor que createdEndDate');
    }
    if (end > now) {
      throw new BadRequestException('createdEndDate no puede ser una fecha futura');
    }
  }

  // Validación fechas de actualización
  if ((updatedStartDate && !updatedEndDate) || (!updatedStartDate && updatedEndDate)) {
    throw new BadRequestException('Debe proporcionar ambas fechas de actualización: updatedStartDate y updatedEndDate');
  }
  if (updatedStartDate && updatedEndDate) {
    const start = new Date(updatedStartDate);
    const end = new Date(updatedEndDate);

    if (isNaN(start.getTime()) || isNaN(end.getTime())) {
      throw new BadRequestException('Fechas de actualización inválidas, formato esperado YYYY-MM-DD');
    }
    if (start > end) {
      throw new BadRequestException('updatedStartDate no puede ser mayor que updatedEndDate');
    }
    if (end > now) {
      throw new BadRequestException('updatedEndDate no puede ser una fecha futura');
    }
  }

  const brandIdsArray = brandIds ? brandIds.split(',').map(id => parseInt(id.trim())) : undefined;
  const supplierIdsArray = supplierIds ? supplierIds.split(',').map(id => parseInt(id.trim())) : undefined;

  const isActiveBoolean = typeof isActive === 'string'
    ? isActive.toLowerCase() === 'true'
      ? true
      : isActive.toLowerCase() === 'false'
        ? false
        : undefined
    : undefined;

  return this.productsService.findAll({
    search,
    createdStartDate,
    createdEndDate,
    updatedStartDate,
    updatedEndDate,
    isActive: isActiveBoolean,
    brandIds: brandIdsArray,
    supplierIds: supplierIdsArray
  });
}

  @Post()
  @ApiOperation({ 
    summary: 'Crear nuevo producto',
    description: 'Crea un nuevo producto en el sistema. El código debe ser único.'
  })
  @ApiResponse({ 
    status: 201, 
    description: 'Producto creado exitosamente',
    type: Product,
    examples: {
      'Producto creado': {
        summary: 'Ejemplo de producto creado',
        value: {
          product_id: 4,
          code: "MBP-14",
          name: "MacBook Pro 14\"",
          description: "Laptop profesional con chip M1 Pro",
          price: 32999,
          brand_id: 1,
          is_active: true,
          created_at: "2023-07-10",
          updated_at: "2023-07-10",
          brand: {
            brand_id: 1,
            name: "Apple",
            description: "Empresa líder en tecnología",
            is_active: true,
            created_at: "2023-01-01",
            updated_at: "2023-01-01"
          }
        }
      }
    }
  })
  @ApiResponse({ 
    status: 400, 
    description: 'Datos inválidos o marca no encontrada',
    examples: {
      'Datos faltantes': {
        summary: 'Error de validación',
        value: {
          statusCode: 400,
          message: [
            'code should not be empty',
            'name should not be empty',
            'price must be a positive number'
          ],
          error: 'Bad Request'
        }
      },
      'Marca no existe': {
        summary: 'Marca no encontrada',
        value: {
          statusCode: 400,
          message: 'La marca especificada no existe',
          error: 'Bad Request'
        }
      }
    }
  })
  @ApiResponse({ 
    status: 401, 
    description: 'No autorizado',
    examples: {
      'Token inválido': {
        summary: 'Error de autenticación',
        value: {
          statusCode: 401,
          message: 'Token inválido o no proporcionado',
          error: 'Unauthorized'
        }
      }
    }
  })
  @ApiResponse({ 
    status: 409, 
    description: 'El código de producto ya existe',
    examples: {
      'Código duplicado': {
        summary: 'Conflicto de código',
        value: {
          statusCode: 409,
          message: 'El código de producto ya existe',
          error: 'Conflict'
        }
      }
    }
  })
  async create(
    @Body() createProductDto: CreateProductDto,
    @CurrentUser() user: User
  ) {
    if (!user) {
      throw new UnauthorizedException('Token inválido o no proporcionado');
    }
    return this.productsService.create(createProductDto, user);
  }

  @Put(':id')
  @ApiOperation({ 
    summary: 'Actualizar producto completamente',
    description: 'Reemplaza todos los campos del producto. Para actualización parcial use PATCH.'
  })
  @ApiParam({ 
    name: 'id', 
    type: Number,
    description: 'ID del producto a actualizar',
    example: 1
  })
  @ApiResponse({ 
    status: 200, 
    description: 'Producto actualizado exitosamente',
    type: Product,
    examples: {
      'Producto actualizado': {
        summary: 'Ejemplo de producto actualizado',
        value: {
          product_id: 1,
          code: "IP13-128-NEW",
          name: "iPhone 13 128GB (2023 Edition)",
          description: "Smartphone con chip A15 Bionic y nueva cámara",
          price: 18999,
          brand_id: 1,
          is_active: true,
          created_at: "2023-01-01",
          updated_at: "2023-07-15",
          brand: {
            brand_id: 1,
            name: "Apple",
            description: "Empresa líder en tecnología",
            is_active: true,
            created_at: "2023-01-01",
            updated_at: "2023-01-01"
          }
        }
      }
    }
  })
  @ApiResponse({ 
    status: 400, 
    description: 'Datos inválidos',
    examples: {
      'Datos inválidos': {
        summary: 'Error de validación',
        value: {
          statusCode: 400,
          message: [
            'price must be a positive number'
          ],
          error: 'Bad Request'
        }
      }
    }
  })
  @ApiResponse({ 
    status: 401, 
    description: 'No autorizado',
    examples: {
      'Token inválido': {
        summary: 'Error de autenticación',
        value: {
          statusCode: 401,
          message: 'Token inválido o no proporcionado',
          error: 'Unauthorized'
        }
      }
    }
  })
  @ApiResponse({ 
    status: 404, 
    description: 'Producto no encontrado',
    examples: {
      'Producto no existe': {
        summary: 'Producto no encontrado',
        value: {
          statusCode: 404,
          message: 'Producto no encontrado',
          error: 'Not Found'
        }
      }
    }
  })
  @ApiResponse({ 
    status: 409, 
    description: 'El código de producto ya existe',
    examples: {
      'Código duplicado': {
        summary: 'Conflicto de código',
        value: {
          statusCode: 409,
          message: 'El código de producto ya existe',
          error: 'Conflict'
        }
      }
    }
  })
  async update(
    @Param('id') id: string,
    @Body() updateProductDto: UpdateProductDto,
    @CurrentUser() user: User
  ) {
    if (!user) {
      throw new UnauthorizedException('Token inválido o no proporcionado');
    }
    return this.productsService.update(+id, updateProductDto, user);
  }

  @Delete(':id')
  @ApiOperation({ 
    summary: 'Desactivar producto (eliminación lógica)',
    description: 'Desactiva un producto cambiando su estado is_active a false'
  })
  @ApiParam({ 
    name: 'id', 
    type: Number,
    description: 'ID del producto a desactivar',
    example: 1
  })
  @ApiResponse({ 
    status: 200, 
    description: 'Producto desactivado exitosamente',
    type: Product,
    examples: {
      'Producto desactivado': {
        summary: 'Ejemplo de producto desactivado',
        value: {
          product_id: 1,
          code: "IP13-128",
          name: "iPhone 13 128GB",
          description: "Smartphone con chip A15 Bionic",
          price: 17999,
          brand_id: 1,
          is_active: false,
          created_at: "2023-01-01",
          updated_at: "2023-07-15",
          brand: {
            brand_id: 1,
            name: "Apple",
            description: "Empresa líder en tecnología",
            is_active: true,
            created_at: "2023-01-01",
            updated_at: "2023-01-01"
          }
        }
      }
    }
  })
  @ApiResponse({ 
    status: 401, 
    description: 'No autorizado',
    examples: {
      'Token inválido': {
        summary: 'Error de autenticación',
        value: {
          statusCode: 401,
          message: 'Token inválido o no proporcionado',
          error: 'Unauthorized'
        }
      }
    }
  })
  @ApiResponse({ 
    status: 404, 
    description: 'Producto no encontrado',
    examples: {
      'Producto no existe': {
        summary: 'Producto no encontrado',
        value: {
          statusCode: 404,
          message: 'Producto no encontrado',
          error: 'Not Found'
        }
      }
    }
  })
  async remove(
    @Param('id') id: string,
    @CurrentUser() user: User
  ) {
    if (!user) {
      throw new UnauthorizedException('Token inválido o no proporcionado');
    }
    return this.productsService.deactivate(+id, user);
  }
}