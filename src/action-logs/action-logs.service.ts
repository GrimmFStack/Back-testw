import { Injectable, NotFoundException, BadRequestException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { ActionLog } from './entities/action-log.entity';
import { User } from '../users/entities/user.entity';
import { LogsView } from './entities/logs-view.entity';

@Injectable()
export class ActionLogsService {
  constructor(
    @InjectRepository(ActionLog)
    private actionLogRepository: Repository<ActionLog>,

    @InjectRepository(User)
    private userRepository: Repository<User>,

    @InjectRepository(LogsView)
    private logsViewRepository: Repository<LogsView>,
  ) {}

  async logAction(logData: {
    userId: number;
    actionType: string;
    entityType: string;
    entityId?: number;
    oldValue?: any;
    newValue?: any;
    ipAddress?: string;
  }): Promise<ActionLog> {
    const user = await this.userRepository.findOne({
      where: { user_id: logData.userId },
    });

    if (!user) {
      throw new NotFoundException(`User with ID ${logData.userId} not found`);
    }

    const log = this.actionLogRepository.create({
      user,
      userId: user.user_id,
      actionType: logData.actionType,
      tableAffected: logData.entityType,
      recordId: logData.entityId,
      oldValues: logData.oldValue,
      newValues: logData.newValue,
    });

    return this.actionLogRepository.save(log);
  }

  async findAllWithFilters(filters: {
    userId?: number;
    actionType?: string;
    tableAffected?: string;
    startDate?: string;
    endDate?: string;
  }): Promise<LogsView[]> {
    const query = this.logsViewRepository.createQueryBuilder('log');

    if (filters.userId) {
      query.andWhere('log.user_id = :userId', { userId: filters.userId });
    }

    if (filters.actionType) {
  query.andWhere('UPPER(log.action_type) = :actionType', {
    actionType: filters.actionType.toUpperCase(),
  });
}

    if (filters.tableAffected) {
      query.andWhere('log.table_affected = :tableAffected', {
        tableAffected: filters.tableAffected,
      });
    }

    if (filters.startDate && !filters.endDate) {
  throw new BadRequestException('Debe proporcionar una fecha de fin si se especifica la fecha de inicio');
}

const now = new Date();
if (filters.startDate && new Date(filters.startDate) > now) {
  throw new BadRequestException('La fecha de inicio no puede estar en el futuro');
}

if (filters.endDate && new Date(filters.endDate) > now) {
  throw new BadRequestException('La fecha de fin no puede estar en el futuro');
}

if (filters.startDate && filters.endDate && filters.startDate > filters.endDate) {
  throw new BadRequestException('La fecha de inicio no puede ser mayor que la fecha de fin');
}

    if (filters.startDate && filters.endDate) {
      query.andWhere('log.action_timestamp BETWEEN :startDate AND :endDate', {
        startDate: filters.startDate,
        endDate: filters.endDate,
      });
    }

    const logs = await query.orderBy('log.action_timestamp', 'DESC').getMany();

    return logs;
  }

  // Ejemplo del formato de retorno de findAllWithFilters:
  /*
  [
    {
      "log_id": 1,
      "user_id": 5,
      "action_type": "UPDATE",
      "table_affected": "brand",
      "record_id": 2,
      "old_values": {"name": "OldName"},
      "new_values": {"name": "NewName"},
      "action_timestamp": "2024-04-15T12:00:00.000Z"
    }
  ]
  */
}
