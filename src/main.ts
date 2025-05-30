import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import { ValidationPipe } from '@nestjs/common';
import { BooleanToStringInterceptor } from './interceptors/boolean-to-string.interceptor';
import { FormatResponseInterceptor } from './interceptors/format-response.interceptor';
import { NestExpressApplication } from '@nestjs/platform-express';
import { join } from 'path';
async function bootstrap() {
  const app = await NestFactory.create<NestExpressApplication>(AppModule);

  app.useGlobalInterceptors(new FormatResponseInterceptor());
  app.useGlobalInterceptors(new BooleanToStringInterceptor());
  app.useGlobalPipes(new ValidationPipe({ whitelist: true, transform: true }));
  app.setBaseViewsDir(join(__dirname, 'views'));
  app.setViewEngine('hbs');
  const config = new DocumentBuilder()
    .setTitle('Mi API')
    .setDescription('API con NestJS, JWT, Swagger y Sequelize')
    .setVersion('1.0')
    .addBearerAuth()
    .build();

  const document = SwaggerModule.createDocument(app, config);
  SwaggerModule.setup('api', app, document);

  const port = process.env.PORT || 3000;
  app.enableCors({
    origin: process.env.FRONTEND_URL, 
    methods: 'GET,POST,PUT,PATCH,DELETE',
    credentials: true,
  });
  await app.listen(port);
  console.log(`App running on port ${port}`);
}
bootstrap();
