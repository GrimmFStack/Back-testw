import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import { ValidationPipe } from '@nestjs/common';
import { BooleanToStringInterceptor } from './interceptors/boolean-to-string.interceptor';
import { FormatResponseInterceptor } from './interceptors/format-response.interceptor';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  app.useGlobalInterceptors(new FormatResponseInterceptor());
  app.useGlobalInterceptors(new BooleanToStringInterceptor());
  app.useGlobalPipes(new ValidationPipe({ whitelist: true, transform: true }));

  const config = new DocumentBuilder()
    .setTitle('Mi API')
    .setDescription('API con NestJS, JWT, Swagger y Sequelize')
    .setVersion('1.0')
    .addBearerAuth()
    .build();

  const document = SwaggerModule.createDocument(app, config);
  SwaggerModule.setup('api', app, document);

  const port = process.env.PORT || 3000;
  await app.listen(port);
  console.log(`App running on port ${port}`);
}
bootstrap();
