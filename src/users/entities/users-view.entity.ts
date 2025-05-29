import { ViewEntity, ViewColumn } from 'typeorm';

@ViewEntity({
  name: 'users_view',
})
export class UsersView {
  @ViewColumn()
  user_id: number;

  @ViewColumn()
  email: string;

  @ViewColumn()
  is_active: boolean;

  @ViewColumn()
  created_at: Date;

  @ViewColumn()
  updated_at: Date;
}
