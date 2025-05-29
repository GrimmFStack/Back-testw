import {
  Controller,
  Get,
  Post,
  Body,
  Param,
  Put,
  Delete,
  Patch,
  Query,
  UseGuards,
  UnauthorizedException,
  NotFoundException,
} from '@nestjs/common';
import { CreateBrandDto } from './dto/create-brand.dto';
import { BrandService } from './brand.service'; // Nombre corregido
import { UpdateBrandDto } from './dto/update-brand.dto';
import { BadRequestException } from '@nestjs/common/exceptions/bad-request.exception';
import {
  ApiTags,
  ApiBearerAuth,
  ApiOperation,
  ApiResponse,
  ApiParam,
  ApiQuery,
} from '@nestjs/swagger';
import { Brand } from './entities/brand.entity';
import { CurrentUser } from '../auth/decorators/current-user-decorator';
import { User } from '../users/entities/user.entity';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { BrandView } from './entities/brands-view.entity';

@ApiTags('Brands')
@ApiBearerAuth()
@UseGuards(JwtAuthGuard)
@Controller('brands')
export class BrandsController {
  constructor(private readonly brandsService: BrandService) {} // Nombre corregido

 @Get()
@ApiOperation({ summary: 'Obtener marcas con filtros' })
@ApiQuery({ name: 'brandName', required: false, type: String, description: 'Nombre de la marca (parcial o completo)' })
@ApiQuery({ name: 'supplierId', required: false, type: Number, description: 'ID del proveedor' })
@ApiQuery({ name: 'isActive', required: false, type: Boolean, description: 'Estado activo de la marca (true o false)' })
@ApiQuery({ name: 'createdStartDate', required: false, type: String, description: 'Fecha inicial de creación (YYYY-MM-DD)' })
@ApiQuery({ name: 'createdEndDate', required: false, type: String, description: 'Fecha final de creación (YYYY-MM-DD)' })
@ApiQuery({ name: 'updatedStartDate', required: false, type: String, description: 'Fecha inicial de actualización (YYYY-MM-DD)' })
@ApiQuery({ name: 'updatedEndDate', required: false, type: String, description: 'Fecha final de actualización (YYYY-MM-DD)' })
@ApiResponse({
  status: 200,
  description: 'Lista filtrada de marcas',
  type: [BrandView],
})
@ApiResponse({ status: 401, description: 'Token inválido o no proporcionado' })
async findAll(
  @Query('brandName') brandName?: string,
  @Query('supplierId') supplierId?: number,
  @Query('isActive') isActive?: boolean,
  @Query('createdStartDate') createdStartDate?: string,
  @Query('createdEndDate') createdEndDate?: string,
  @Query('updatedStartDate') updatedStartDate?: string,
  @Query('updatedEndDate') updatedEndDate?: string,
  @CurrentUser() user?: User,
): Promise<BrandView[]> {
  if (!user) {
    throw new UnauthorizedException('Token inválido o usuario no autenticado');
  }

  return this.brandsService.findAllWithFilters({
    brandName,
    supplierId,
    isActive,
    createdStartDate,
    createdEndDate,
    updatedStartDate,
    updatedEndDate,
  });
}


  // @Get('search')
  // @ApiOperation({ summary: 'Buscar marcas de TI con filtros avanzados' })
  // @ApiQuery({ name: 'name', required: false, type: String, description: 'Filtrar por nombre (texto parcial)' })
  // @ApiQuery({ name: 'createdStartDate', required: false, type: String, description: 'Fecha inicio creación (YYYY-MM-DD)' })
  // @ApiQuery({ name: 'createdEndDate', required: false, type: String, description: 'Fecha fin creación (YYYY-MM-DD)' })
  // @ApiQuery({ name: 'updatedStartDate', required: false, type: String, description: 'Fecha inicio actualización (YYYY-MM-DD)' })
  // @ApiQuery({ name: 'updatedEndDate', required: false, type: String, description: 'Fecha fin actualización (YYYY-MM-DD)' })
  // @ApiQuery({ name: 'isActive', required: false, type: Boolean, description: 'Estado activo/inactivo' })
  // @ApiResponse({ status: 200, description: 'Lista filtrada de marcas de TI', type: [Brand] })
  // @ApiResponse({ status: 401, description: 'Token inválido o no proporcionado' })
  // async search(
  //   @Query('name') name?: string,
  //   @Query('createdStartDate') createdStartDate?: string,
  //   @Query('createdEndDate') createdEndDate?: string,
  //   @Query('updatedStartDate') updatedStartDate?: string,
  //   @Query('updatedEndDate') updatedEndDate?: string,
  //   @Query('isActive') isActive?: string,
  //   @CurrentUser() user: User,
  // ) {
  //   if (!user) {
  //     throw new UnauthorizedException('Token inválido o usuario no autenticado');
  //   }

  //   const parsedIsActive =
  //     isActive === 'true' ? true : isActive === 'false' ? false : undefined;

  //   const filters = {
  //     name,
  //     createdStartDate,
  //     createdEndDate,
  //     updatedStartDate,
  //     updatedEndDate,
  //     isActive: parsedIsActive,
  //   };

  //   return this.brandsService.findAllWithFilters(filters);
  // }

  @Get(':id')
@ApiOperation({ summary: 'Obtener una marca de TI por ID' })
@ApiParam({
  name: 'id',
  type: Number,
  description: 'ID de la marca',
  example: 1,
})
@ApiResponse({
  status: 200,
  description: 'Marca de TI encontrada',
  schema: {
    example: {
      id: 1,
      name: 'Microsoft',
      description: 'Empresa líder en software y servicios en la nube',
      isActive: 'Sí'
    }
  }
})
@ApiResponse({ status: 400, description: 'ID inválido' })
@ApiResponse({ status: 401, description: 'Token inválido o no proporcionado' })
@ApiResponse({ status: 404, description: 'Marca no encontrada' })
async findOne(@Param('id') id: string) {

  if (isNaN(+id)) {
    throw new BadRequestException('ID inválido');
  }

  const brand = await this.brandsService.findOneMinimal(+id);
  
  if (!brand) {
    throw new NotFoundException('Marca no encontrada');
  }

  return {
    id: brand.id,
    name: brand.name,
    description: brand.description,
    isActive: brand.isActive ? 'Sí' : 'No'
  };
}


  @Post()
  @ApiOperation({ summary: 'Crear nueva marca de TI' })
  @ApiResponse({
    status: 201,
    description: 'Marca de TI creada',
    type: Brand,
    examples: {
      'Marca creada': {
        summary: 'Ejemplo de marca creada exitosamente',
        value: {
          brandId: 4,
          name: 'NVIDIA',
          description: 'Fabricante líder de GPUs y tecnología gráfica',
          isActive: true,
          createdAt: '2023-07-01',
          updatedAt: '2023-07-01',
        },
      },
    },
  })
  @ApiResponse({
    status: 400,
    description: 'Datos inválidos',
    examples: {
      'Nombre faltante': {
        summary: 'Error de validación',
        value: {
          statusCode: 400,
          message: ['name should not be empty'],
          error: 'Bad Request',
        },
      },
    },
  })
  @ApiResponse({ status: 401, description: 'Token inválido o no proporcionado' })
  @ApiResponse({
    status: 409,
    description: 'El nombre de la marca ya existe',
    examples: {
      'Conflicto de nombre': {
        summary: 'Marca ya existente',
        value: {
          statusCode: 409,
          message: 'El nombre de la marca ya existe',
          error: 'Conflict',
        },
      },
    },
  })
  async create(@Body() createBrandDto: CreateBrandDto, @CurrentUser() user: User) {
    if (!user) {
      throw new UnauthorizedException('Token inválido o usuario no autenticado');
    }
    return this.brandsService.create(createBrandDto, user.user_id);
  }

  @Put(':id')
  @ApiOperation({ summary: 'Actualizar marca de TI completamente' })
  @ApiParam({
    name: 'id',
    type: Number,
    description: 'ID de la marca a actualizar',
    example: 1,
  })
  @ApiResponse({
    status: 200,
    description: 'Marca de TI actualizada',
    type: Brand,
    examples: {
      'Marca actualizada': {
        summary: 'Ejemplo de marca actualizada',
        value: {
          brandId: 1,
          name: 'Microsoft Corporation',
          description: 'Empresa multinacional de tecnología con sede en Redmond',
          isActive: true,
          createdAt: '2023-01-15',
          updatedAt: '2023-07-05',
        },
      },
    },
  })
  @ApiResponse({ status: 401, description: 'Token inválido o no proporcionado' })
  @ApiResponse({ status: 404, description: 'Marca no encontrada' })
  @ApiResponse({ status: 409, description: 'El nombre de la marca ya existe' })
  async update(
    @Param('id') id: string,
    @Body() updateBrandDto: UpdateBrandDto,
    @CurrentUser() user: User,
  ) {
    if (!user) {
      throw new UnauthorizedException('Token inválido o usuario no autenticado');
    }
    return this.brandsService.update(+id, updateBrandDto, user.user_id);
  }

  @Delete(':id')
  @ApiOperation({ summary: 'Desactivar marca de TI (eliminación lógica)' })
  @ApiParam({
    name: 'id',
    type: Number,
    description: 'ID de la marca a desactivar',
    example: 2,
  })
  @ApiResponse({
    status: 200,
    description: 'Marca de TI desactivada',
    type: Brand,
    examples: {
      'Marca desactivada': {
        summary: 'Ejemplo de marca desactivada',
        value: {
          brandId: 2,
          name: 'Apple',
          description: 'Fabricante de hardware y software premium',
          isActive: false,
          createdAt: '2023-02-10',
          updatedAt: '2023-07-05',
        },
      },
    },
  })
  @ApiResponse({ status: 401, description: 'Token inválido o no proporcionado' })
  @ApiResponse({ status: 404, description: 'Marca no encontrada' })
  async remove(@Param('id') id: string, @CurrentUser() user: User) {
    if (!user) {
      throw new UnauthorizedException('Token inválido o usuario no autenticado');
    }
    return this.brandsService.deactivate(+id, user.user_id);
  }

  @Patch(':id/activate')
  @ApiOperation({ summary: 'Reactivar marca de TI' })
  @ApiParam({
    name: 'id',
    type: Number,
    description: 'ID de la marca a reactivar',
    example: 3,
  })
  @ApiResponse({
    status: 200,
    description: 'Marca de TI reactivada',
    type: Brand,
    examples: {
      'Marca reactivada': {
        summary: 'Ejemplo de marca reactivada',
        value: {
          brandId: 3,
          name: 'BlackBerry',
          description: 'Antiguo fabricante de smartphones',
          isActive: true,
          createdAt: '2023-01-20',
          updatedAt: '2023-07-05',
        },
      },
    },
  })
  @ApiResponse({ status: 401, description: 'Token inválido o no proporcionado' })
  @ApiResponse({ status: 404, description: 'Marca no encontrada' })
  async activate(@Param('id') id: string, @CurrentUser() user: User) {
    if (!user) {
      throw new UnauthorizedException('Token inválido o usuario no autenticado');
    }
    return this.brandsService.activate(+id, user.user_id);
  }
}
