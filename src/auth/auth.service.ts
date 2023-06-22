import { Injectable, UnauthorizedException } from '@nestjs/common'
import { JwtService } from '@nestjs/jwt'
import { InjectModel } from '@nestjs/mongoose'
import { Model } from 'mongoose'
import { User } from './schemas/user.schema'

import * as bcrypt from 'dcryptjs'
import { LoginDto } from './dto/login.dto'
import { SingUpDto } from './dto/singup.dto'

@Injectable()
export class AuthService {
	constructor(
		@InjectModel(User.name)
		private userModel: Model<User>,
		private jwtService: JwtService,
	) {}

	async singUp(singUdDto: SingUpDto): Promise<{ token: string }> {
		const { name, email, password } = singUdDto

		const hashedPassword = await bcrypt.hash(password, 10)

		const user = await this.userModel.create({
			name,
			email,
			password: hashedPassword,
		})

		const token = this.jwtService.sign({ id: user._id })

		return { token }
	}

	async login(loginDto: LoginDto): Promise<{ token: string }> {
		const { email, password } = loginDto

		const user = await this.userModel.findOne({ email })

		if (!user) {
			throw new UnauthorizedException('Incalid email or password')
		}

		const isPasswoedMatched = await bcrypt.compare(password, user.password)

		if (!isPasswoedMatched) {
			throw new UnauthorizedException('Incalid email or password')
		}

		const token = this.jwtService.sign({ id: user._id })

		return { token }
	}
}
