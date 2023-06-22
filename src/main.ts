import { ValidationPipe } from '@nestjs/common'
import { NestFactory } from '@nestjs/core'
import { AppModule } from './app.module'

async function bootstrap() {
	const app = await NestFactory.create(AppModule)
	const PORT = process.env.PORT

	app.useGlobalPipes(new ValidationPipe())

	await app.listen(PORT, () => {
		console.log(`SERVER WORK. PORT: ${PORT}`)
	})
}
bootstrap()
