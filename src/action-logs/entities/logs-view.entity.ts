// src/logs/entities/logs-view.entity.ts
import { ViewEntity, ViewColumn } from 'typeorm';

@ViewEntity({ name: 'logs_view' })
export class LogsView {
  @ViewColumn({ name: 'log_id' })
  logId: number;

  @ViewColumn({ name: 'user_id' })
  userId: number;

  @ViewColumn({ name: 'action_type' })
  actionType: string;

  @ViewColumn({ name: 'table_affected' })
  tableAffected: string;

  @ViewColumn({ name: 'record_id' })
  recordId: number;

  @ViewColumn({ name: 'old_values' })
  oldValues: string;

  @ViewColumn({ name: 'new_values' })
  newValues: string;

  @ViewColumn({ name: 'action_timestamp' })
  actionTimestamp: Date;
}
