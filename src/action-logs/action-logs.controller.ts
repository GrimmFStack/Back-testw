import { Controller, Get, Query, UseGuards, UnauthorizedException} from '@nestjs/common';
import { ActionLogsService } from './action-logs.service';
import { ApiTags, ApiBearerAuth, ApiOperation, ApiResponse, ApiQuery } from '@nestjs/swagger';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { LogsView } from './entities/logs-view.entity';
import { User } from '../users/entities/user.entity';
import { CurrentUser } from '../auth/decorators/current-user-decorator';



@ApiTags('Logs')
@ApiBearerAuth()
@UseGuards(JwtAuthGuard)
@Controller('logs')
export class ActionLogsController {
  constructor(private readonly actionLogsService: ActionLogsService) {}

  @Get()
  @ApiOperation({ summary: 'Obtener logs de acciones con filtros combinados' })
  @ApiQuery({ name: 'userId', required: false, type: Number })
  @ApiQuery({ name: 'actionType', required: false, type: String })
  @ApiQuery({ name: 'tableAffected', required: false, type: String })
  @ApiQuery({ name: 'startDate', required: false, type: String, description: 'Formato: YYYY-MM-DD' })
  @ApiQuery({ name: 'endDate', required: false, type: String, description: 'Formato: YYYY-MM-DD' })
  @ApiResponse({
    status: 200,
    description: 'Lista de logs de acciones',
    type: [LogsView],
    examples: {
      'Respuesta de ejemplo': {
        summary: 'Ejemplo con múltiples logs',
        value: [
          {
            log_id: 1,
            user_id: 3,
            action_type: 'UPDATE',
            table_affected: 'brand',
            record_id: 2,
            old_values: {
              name: 'Old Brand Name',
              description: 'Old description'
            },
            new_values: {
              name: 'New Brand Name',
              description: 'Updated description'
            },
            action_timestamp: '2024-12-15T10:45:00Z',
          },
        ],
      },
    },
  })
  @ApiResponse({
  status: 400,
  description: 'Debe proporcionar una fecha de fin si se especifica la fecha de inicio',
})
@ApiResponse({ status: 400, description: 'La fecha de inicio no puede estar en el futuro' })
@ApiResponse({ status: 400, description: 'La fecha de fin no puede estar en el futuro' })
@ApiResponse({ status: 400, description: 'La fecha de inicio no puede ser mayor que la fecha de fin' })

  @ApiResponse({ status: 401, description: 'Token inválido o no proporcionado' })
  async findAllWithFilters(
    @Query('userId') userId?: number,
    @Query('actionType') actionType?: string,
    @Query('tableAffected') tableAffected?: string,
    @Query('startDate') startDate?: string,
    @Query('endDate') endDate?: string,
    @CurrentUser() user?: User,
  ) {
    if (!user) {
      throw new UnauthorizedException('Token inválido o usuario no autenticado');
    }

    return this.actionLogsService.findAllWithFilters({
      userId,
      actionType,
      tableAffected,
      startDate,
      endDate,
    });
  }
}