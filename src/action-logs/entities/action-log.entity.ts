import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  ManyToOne,
  JoinColumn,
  CreateDateColumn,
} from 'typeorm';
import { User } from '../../users/entities/user.entity';

@Entity('action_logs')
export class ActionLog {
  @PrimaryGeneratedColumn({ name: 'log_id', type: 'bigint' })
  id: number;

  @ManyToOne(() => User)
  @JoinColumn({ name: 'user_id' })
  user: User;

  @Column({ name: 'user_id', type: 'bigint' })
  userId: number;

  @Column({ name: 'action_type', length: 50 })
  actionType: string;

  @Column({ name: 'table_affected', length: 50 })
  tableAffected: string;

  @Column({ name: 'record_id', type: 'bigint' })
  recordId: number;

  @Column({ name: 'old_values', type: 'json', nullable: true })
  oldValues: any;

  @Column({ name: 'new_values', type: 'json', nullable: true })
  newValues: any;

  @CreateDateColumn({
    name: 'action_timestamp',
    type: 'date',
    default: () => 'CURRENT_DATE',
  })
  actionTimestamp: Date;
}
