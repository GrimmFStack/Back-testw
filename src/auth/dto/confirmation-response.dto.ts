import { ApiProperty } from '@nestjs/swagger';

export class ConfirmationResponseDto {
  @ApiProperty({ example: true, description: 'Indica si la operación fue exitosa' })
  success: boolean;

  @ApiProperty({ example: 'Cuenta activada correctamente', description: 'Mensaje descriptivo' })
  message: string;

  @ApiProperty({ example: 'https://tu-frontend.com/confirmacion-exitosa', description: 'URL de redirección' })
  redirectUrl: string;
}
