import { Controller, Get, Post, Body, Param, Put, Patch, Delete, ParseIntPipe, UseGuards, Request, Query, BadRequestException, NotFoundException } from '@nestjs/common';
import { BrandSuppliersService } from './brand-suppliers.service';
import { CreateBrandSupplierDto } from './dto/create-brand-supplier.dto';
import { UpdateBrandSupplierDto } from './dto/update-brand-supplier.dto';
import { ApiOperation, ApiResponse, ApiTags, ApiParam, ApiBody, ApiQuery, ApiBearerAuth } from '@nestjs/swagger';
import { BrandSupplier } from './entities/brand-supplier.entity';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { User } from '../users/entities/user.entity';
import { BrandSupplierView } from './entities/brand-suppliers-view.entity';


@ApiTags('Proveedores de Marcas')
@Controller('brand-suppliers')
@ApiBearerAuth()
@UseGuards(JwtAuthGuard)
export class BrandSuppliersController {
  constructor(private readonly brandSuppliersService: BrandSuppliersService) {}
@Get()
@ApiOperation({
  summary: 'Buscar proveedores con filtros combinados',
  description: 'Permite buscar proveedores por nombre, marca, fechas de creación/edición o marca. Todos los parámetros son opcionales.'
})
@ApiQuery({
  name: 'search',
  required: false,
  type: String,
  description: 'Texto para buscar en nombre del proveedor, persona de contacto, email o marca',
  example: 'Samsung'
})
@ApiQuery({
  name: 'createdStartDate',
  required: false,
  type: String,
  description: 'Fecha inicial de creación (YYYY-MM-DD)',
  example: '2023-01-01'
})
@ApiQuery({
  name: 'createdEndDate',
  required: false,
  type: String,
  description: 'Fecha final de creación (YYYY-MM-DD)',
  example: '2023-12-31'
})
@ApiQuery({
  name: 'updatedStartDate',
  required: false,
  type: String,
  description: 'Fecha inicial de actualización (YYYY-MM-DD)',
  example: '2023-01-01'
})
@ApiQuery({
  name: 'updatedEndDate',
  required: false,
  type: String,
  description: 'Fecha final de actualización (YYYY-MM-DD)',
  example: '2023-12-31'
})
@ApiQuery({
  name: 'brandIds',
  required: false,
  type: String,
  description: 'IDs de marcas separados por comas',
  example: '1,2,3'
})
@ApiQuery({
  name: 'isActive',
  required: false,
  type: Boolean,
  description: 'Filtrar por si el proveedor está activo (true/false)',
  example: 'true'
})
@ApiResponse({
  status: 200,
  description: 'Lista de proveedores encontrados',
  type: BrandSupplierView,
  isArray: true
})
async findAll(
  @Query('search') search?: string,
  @Query('createdStartDate') createdStartDate?: string,
  @Query('createdEndDate') createdEndDate?: string,
  @Query('updatedStartDate') updatedStartDate?: string,
  @Query('updatedEndDate') updatedEndDate?: string,
  @Query('brandIds') brandIds?: string,
  @Query('isActive') isActive?: string
): Promise<BrandSupplierView[]> {
  const brandIdsArray = brandIds
    ? brandIds.split(',').map(id => parseInt(id.trim()))
    : undefined;

  let isActiveBoolean: boolean | undefined = undefined;
  if (isActive === 'true') isActiveBoolean = true;
  else if (isActive === 'false') isActiveBoolean = false;
  else if (isActive !== undefined) {
    throw new BadRequestException('El valor de isActive debe ser "true" o "false".');
  }

  return this.brandSuppliersService.findAll({
    search,
    createdStartDate,
    createdEndDate,
    updatedStartDate,
    updatedEndDate,
    brandIds: brandIdsArray,
    isActive: isActiveBoolean,
  });
}


  @Get(':id')
@ApiOperation({ summary: 'Obtener proveedor por ID' })
@ApiParam({ 
  name: 'id', 
  example: 1, 
  description: 'ID del proveedor',
  type: Number
})
@ApiResponse({
  status: 200,
  description: 'Proveedor encontrado',
  schema: {
    example: {
      id: 1,
      name: "TechSource International",
      contactPerson: "Roberto Mendoza",
      email: "roberto@techsource.com",
      phone: "8005550101",
      address: "123 Tech Valley, Cupertino, CA, USA",
      isActive: "Sí",
      brand: {
        name: "Apple",
        description: "Empresa líder en tecnología conocida por el iPhone, Mac y iPad"
      }
    }
  }
})
@ApiResponse({ 
  status: 404, 
  description: 'Proveedor no encontrado',
  examples: {
    'Proveedor no existe': {
      summary: 'Error cuando el proveedor no existe',
      value: {
        statusCode: 404,
        message: 'Proveedor con ID 999 no encontrado',
        error: 'Not Found'
      }
    }
  }
})
async findOne(@Param('id') id: string) {
  if (isNaN(+id)) {
    throw new BadRequestException('ID inválido');
  }

  const supplier = await this.brandSuppliersService.findOne(+id);
  
  if (!supplier) {
    throw new NotFoundException(`Proveedor con ID ${id} no encontrado`);
  }

  return {
    id: supplier.id,
    name: supplier.name,
    contactPerson: supplier.contactPerson,
    email: supplier.email,
    phone: supplier.phone,
    address: supplier.address,
    isActive: supplier.isActive ? 'Sí' : 'No',
    brand: {
      name: supplier.brand.name,
      description: supplier.brand.description
    }
  };
}
  @ApiResponse({ 
    status: 404, 
    description: 'Proveedor no encontrado',
    examples: {
      'Proveedor no existe': {
        summary: 'Error cuando el proveedor no existe',
        value: {
          statusCode: 404,
          message: 'Proveedor con ID 999 no encontrado',
          error: 'Not Found'
        }
      }
    }
  })

  
  @Post()
@ApiOperation({ 
  summary: 'Crear un nuevo proveedor',
  description: 'Registra un nuevo proveedor en el sistema. El email debe ser único.'
})
@ApiBody({ 
  type: CreateBrandSupplierDto,
  examples: {
    'Proveedor completo': {
      summary: 'Ejemplo con todos los campos',
      value: {
        name: 'Proveedor Completo S.A.',
        contactPerson: 'Ana García',
        email: 'contacto@proveedorcompleto.com',
        phone: '987654321',
        address: 'Calle Ejemplo 123, Lima, Perú',
        brandId: 2,
        isActive: true
      }
    }
  }
})
@ApiResponse({
  status: 201,
  description: 'Proveedor creado exitosamente',
  type: BrandSupplier,
  examples: {
    'Proveedor creado': {
      summary: 'Ejemplo de respuesta exitosa',
      value: {
        id: 2,
        name: 'Distribuidora Textil Nacional',
        contactPerson: 'María García',
        email: 'ventas@textilnacional.com',
        phone: '9123456789',
        address: 'Calle Comercial 456, Lima, Perú',
        isActive: true,
        createdAt: '2023-05-21',
        updatedAt: '2023-05-21',
        brand: {
          id: 2,
          name: 'Adidas'
        }
      }
    }
  }
})
@ApiResponse({ 
  status: 400, 
  description: 'Datos de entrada inválidos',
  examples: {
    'Datos faltantes': {
      summary: 'Error de validación',
      value: {
        statusCode: 400,
        message: [
          'name should not be empty',
          'email must be an email',
          'brandId should not be empty'
        ],
        error: 'Bad Request'
      }
    }
  }
})
@ApiResponse({ 
  status: 409, 
  description: 'El email ya está registrado',
  examples: {
    'Email duplicado': {
      summary: 'Error de conflicto',
      value: {
        statusCode: 409,
        message: 'El email ya está registrado',
        error: 'Conflict'
      }
    }
  }
})
async create(
  @Body() createBrandSupplierDto: CreateBrandSupplierDto,
  @Request() req: { user: User },
): Promise<BrandSupplier> {
  return this.brandSuppliersService.create(createBrandSupplierDto, req.user);
}


  @Put(':id')
  @ApiOperation({ 
    summary: 'Reemplazar completamente un proveedor',
    description: 'Actualiza todos los campos del proveedor. Para actualización parcial use PATCH.'
  })
  @ApiParam({ 
    name: 'id', 
    example: 1, 
    description: 'ID del proveedor a actualizar',
    type: Number
  })
  @ApiBody({ 
    type: CreateBrandSupplierDto,
    examples: {
      'Actualización completa': {
        summary: 'Ejemplo de actualización completa',
        value: {
          name: 'Nuevo Nombre del Proveedor',
          contactPerson: 'Nuevo Contacto',
          email: 'nuevo@email.com',
          phone: '987654321',
          address: 'Nueva Dirección 123',
          brandId: 2,
          isActive: false
        }
      }
    }
  })
  @ApiResponse({
    status: 200,
    description: 'Proveedor actualizado completamente',
    type: BrandSupplier,
    examples: {
      'Proveedor actualizado': {
        summary: 'Ejemplo de respuesta exitosa',
        value: {
          supplierId: 1,
          name: 'Nuevo Nombre del Proveedor',
          contactPerson: 'Nuevo Contacto',
          email: 'nuevo@email.com',
          phone: '987654321',
          address: 'Nueva Dirección 123',
          isActive: false,
          createdAt: '2023-05-15',
          updatedAt: '2023-06-01',
          brand: {
            brandId: 2,
            name: 'Adidas'
          }
        }
      }
    }
  })
  @ApiResponse({ 
    status: 400, 
    description: 'Datos de entrada inválidos'
  })
  @ApiResponse({ 
    status: 404, 
    description: 'Proveedor no encontrado'
  })
  @ApiResponse({ 
    status: 409, 
    description: 'El email ya está registrado'
  })
  async replace(
    @Param('id', ParseIntPipe) id: number,
    @Body() createBrandSupplierDto: CreateBrandSupplierDto,
    @Request() req: { user: User },
  ): Promise<BrandSupplier> {
    return this.brandSuppliersService.replace(id, createBrandSupplierDto, req.user);
  }

  @Patch(':id')
  @ApiOperation({ 
    summary: 'Actualizar parcialmente un proveedor',
    description: 'Actualiza solo los campos proporcionados del proveedor.'
  })
  @ApiParam({ 
    name: 'id', 
    example: 1, 
    description: 'ID del proveedor a actualizar',
    type: Number
  })
  @ApiBody({ 
    type: UpdateBrandSupplierDto,
    examples: {
      'Actualización parcial': {
        summary: 'Ejemplo de actualización parcial',
        value: {
          contactPerson: 'Nuevo Contacto Actualizado',
          phone: '912345678'
        }
      }
    }
  })
  @ApiResponse({
    status: 200,
    description: 'Proveedor actualizado parcialmente',
    type: BrandSupplier,
    examples: {
      'Proveedor actualizado': {
        summary: 'Ejemplo de respuesta exitosa',
        value: {
          supplierId: 1,
          name: 'Proveedor de Materiales Premium S.A.',
          contactPerson: 'Nuevo Contacto Actualizado',
          email: 'contacto@proveedormaterials.com',
          phone: '912345678',
          address: 'Av. Industrial 123, Lima, Perú',
          isActive: true,
          createdAt: '2023-05-15',
          updatedAt: '2023-06-01',
          brand: {
            brandId: 1,
            name: 'Nike'
          }
        }
      }
    }
  })
  @ApiResponse({ 
    status: 400, 
    description: 'Datos de entrada inválidos'
  })
  @ApiResponse({ 
    status: 404, 
    description: 'Proveedor no encontrado'
  })
  @ApiResponse({ 
    status: 409, 
    description: 'El email ya está registrado'
  })
  async update(
    @Param('id', ParseIntPipe) id: number,
    @Body() updateBrandSupplierDto: UpdateBrandSupplierDto,
    @Request() req: { user: User },
  ): Promise<BrandSupplier> {
    return this.brandSuppliersService.update(id, updateBrandSupplierDto, req.user);
  }

  @Delete(':id')
  @ApiOperation({ 
    summary: 'Eliminar un proveedor',
    description: 'Elimina permanentemente un proveedor del sistema.'
  })
  @ApiParam({ 
    name: 'id', 
    example: 1, 
    description: 'ID del proveedor a eliminar',
    type: Number
  })
  @ApiResponse({ 
    status: 200, 
    description: 'Proveedor eliminado exitosamente',
    examples: {
      'Eliminación exitosa': {
        summary: 'Respuesta de éxito',
        value: {
          message: 'Proveedor con ID 1 eliminado exitosamente'
        }
      }
    }
  })
  @ApiResponse({ 
    status: 404, 
    description: 'Proveedor no encontrado'
  })
  async remove(
    @Param('id', ParseIntPipe) id: number,
    @Request() req: { user: User },
  ): Promise<void> {
    return this.brandSuppliersService.remove(id, req.user);
  }
}