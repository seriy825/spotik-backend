import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import * as cookieParser from 'cookie-parser';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  const config = new DocumentBuilder()
    .setTitle('Spotik')
    .setDescription('This is API Documenation of application Spotik.')
    .build();
  const document = SwaggerModule.createDocument(app, config);
  SwaggerModule.setup('api', app, document);

  app.use(cookieParser());
  app.enableCors({
    credentials: true,
    origin: [process.env.FRONT_END_URL, 'https://accounts.google.com'],
  });
  app.setGlobalPrefix('api');
  await app.listen(3001);
}
bootstrap();
