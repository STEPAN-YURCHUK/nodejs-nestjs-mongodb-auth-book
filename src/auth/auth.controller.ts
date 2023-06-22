import { Body, Controller, Get, Post } from '@nestjs/common'
import { AuthService } from './auth.service'
import { LoginDto } from './dto/login.dto'
import { SingUpDto } from './dto/singup.dto'

@Controller('auth')
export class AuthController {
	constructor(private authService: AuthService) {}

	@Post('/singup')
	singUp(@Body() singUpDto: SingUpDto): Promise<{ token: string }> {
		return this.authService.singUp(singUpDto)
	}

	@Get('/login')
	login(@Body() loginDto: LoginDto): Promise<{ token: string }> {
		return this.authService.login(loginDto)
	}
}